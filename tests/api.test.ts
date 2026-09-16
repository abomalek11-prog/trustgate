/**
 * Cross-agent over HTTP: the route handlers are called exactly as Next.js would
 * call them, with real Request objects.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { POST as gate } from '@/app/api/gate/route';
import { GET as demoRequest } from '@/app/api/demo/request/route';
import { POST as revoke } from '@/app/api/demo/revoke/route';
import { GET as listScenarios, POST as runScenarioRoute } from '@/app/api/demo/scenarios/route';
import { GET as agents } from '@/app/api/agents/route';
import { GET as agent } from '@/app/api/agents/[key]/route';
import { GET as getPolicy, PUT as putPolicy } from '@/app/api/policy/route';
import { resetServerWorld } from '@/lib/server/world';
import type { Decision } from '@/lib/policy/types';
import type { ActionRequest } from '@/lib/requests/types';

const HOST = 'http://trustgate.test';

async function fetchRequest(scenario: string, amount?: number): Promise<ActionRequest> {
  const res = await demoRequest(new Request(HOST + '/api/demo/request?scenario=' + scenario + (amount ? '&amount=' + amount : '')));
  expect(res.status).toBe(200);
  return ((await res.json()) as { request: ActionRequest }).request;
}

async function post(handler: (r: Request) => Promise<Response>, path: string, body: unknown) {
  return handler(new Request(HOST + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }));
}

describe('HTTP API', () => {
  beforeEach(() => {
    resetServerWorld();
  });

  it('GET /api/agents lists agents without secret keys', async () => {
    const res = await agents();
    const json = (await res.json()) as { agents: Array<{ slug: string; did: string }> };
    expect(json.agents.map((a) => a.slug).sort()).toEqual(['buyer', 'clone', 'procurement', 'rogue']);
    expect(JSON.stringify(json)).not.toMatch(/secretKey/);
  });

  it('GET /api/agents/:key returns a trust profile (by key or DID) and 404s otherwise', async () => {
    const byKey = await agent(new Request(HOST + '/api/agents/buyer'), { params: Promise.resolve({ key: 'buyer' }) });
    const profile = (await byKey.json()) as { did: string; credentials: unknown[]; grants: unknown[]; attestations: unknown[] };
    expect(profile.credentials).toHaveLength(1);
    expect(profile.grants).toHaveLength(1);
    expect(profile.attestations).toHaveLength(2);
    const byDid = await agent(new Request(HOST + '/api/agents/x'), { params: Promise.resolve({ key: profile.did }) });
    expect(byDid.status).toBe(200);
    const missing = await agent(new Request(HOST + '/api/agents/nope'), { params: Promise.resolve({ key: 'nope' }) });
    expect(missing.status).toBe(404);
  });

  it('POST /api/gate ALLOWs the valid demo request and DENIES the spoofed one', async () => {
    const ok = await post(gate, '/api/gate', { request: await fetchRequest('valid') });
    expect(ok.headers.get('x-trustgate-decision')).toBe('ALLOW');
    const d1 = (await ok.json()) as Decision;
    expect(d1.allow).toBe(true);
    expect(d1.receipt?.proof.proofValue).toMatch(/^z/);

    const bad = await post(gate, '/api/gate', { request: await fetchRequest('spoofed') });
    const d2 = (await bad.json()) as Decision;
    expect(d2.decision).toBe('DENY');
    expect(d2.failedChecks.map((c) => c.id)).toContain('REQUEST_SIGNATURE_VALID');
  });

  it('POST /api/gate accepts a bare ActionRequest body too', async () => {
    const res = await post(gate, '/api/gate', await fetchRequest('valid'));
    expect(((await res.json()) as Decision).decision).toBe('ALLOW');
  });

  it('replaying the same envelope over HTTP is DENIED', async () => {
    const req = await fetchRequest('valid');
    expect(((await (await post(gate, '/api/gate', { request: req })).json()) as Decision).decision).toBe('ALLOW');
    const replay = (await (await post(gate, '/api/gate', { request: req })).json()) as Decision;
    expect(replay.decision).toBe('DENY');
    expect(replay.failedChecks.map((c) => c.id)).toContain('NONCE_UNSEEN');
  });

  it('revocation over HTTP flips the decision', async () => {
    const req = await fetchRequest('valid');
    const credentialId = req.presentation.credentials[0].id;
    const r = await post(revoke, '/api/demo/revoke', { credentialId, revoked: true });
    expect(((await r.json()) as { revokedIndices: number[] }).revokedIndices).toEqual([42]);
    const d = (await (await post(gate, '/api/gate', { request: await fetchRequest('valid') })).json()) as Decision;
    expect(d.failedChecks.map((c) => c.id)).toContain('CREDENTIAL_NOT_REVOKED');
    await post(revoke, '/api/demo/revoke', { credentialId, revoked: false });
    const d2 = (await (await post(gate, '/api/gate', { request: await fetchRequest('valid') })).json()) as Decision;
    expect(d2.decision).toBe('ALLOW');
  });

  it('a per-request policy override changes the decision without mutating the server policy', async () => {
    const before = (await (await getPolicy()).json()) as { policyHash: string; policy: { require: { authority: { maxAmount: { value: number } } } } };
    const tight = { ...before.policy, require: { ...before.policy.require, authority: { ...before.policy.require.authority, maxAmount: { value: 100, currency: 'USD' } } } };
    const d = (await (await post(gate, '/api/gate', { request: await fetchRequest('valid'), policy: tight })).json()) as Decision;
    expect(d.decision).toBe('DENY');
    expect(d.failedChecks.map((c) => c.id)).toContain('POLICY_AMOUNT_WITHIN_LIMIT');
    const after = (await (await getPolicy()).json()) as { policyHash: string };
    expect(after.policyHash).toBe(before.policyHash);
  });

  it('PUT /api/policy persists a new policy for the instance', async () => {
    const cur = (await (await getPolicy()).json()) as { policy: { require: { trustedIssuers: string[] } } };
    const res = await putPolicy(new Request(HOST + '/api/policy', { method: 'PUT', body: JSON.stringify({ ...cur.policy, require: { ...cur.policy.require, trustedIssuers: [] } }) }));
    expect(res.status).toBe(200);
    const d = (await (await post(gate, '/api/gate', { request: await fetchRequest('valid') })).json()) as Decision;
    expect(d.failedChecks.map((c) => c.id)).toContain('CREDENTIAL_ISSUER_TRUSTED');
  });

  it('scenario endpoints list and run attacks', async () => {
    const list = (await (await listScenarios()).json()) as { scenarios: Array<{ id: string }> };
    expect(list.scenarios.length).toBeGreaterThanOrEqual(12);
    const run = await post(runScenarioRoute, '/api/demo/scenarios', { id: 'overscope' });
    expect(run.headers.get('x-trustgate-decision')).toBe('DENY');
    const json = (await run.json()) as { decision: Decision };
    expect(json.decision.failedChecks.map((c) => c.id)).toContain('AUTHORITY_AMOUNT_WITHIN_GRANT');
  });

  it('rejects malformed bodies with 400', async () => {
    const res = await gate(new Request(HOST + '/api/gate', { method: 'POST', body: 'not json' }));
    expect(res.status).toBe(400);
    const res2 = await post(gate, '/api/gate', { hello: 'world' });
    expect(res2.status).toBe(400);
    const res3 = await demoRequest(new Request(HOST + '/api/demo/request?scenario=nope'));
    expect(res3.status).toBe(400);
  });
});
