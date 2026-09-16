import { describe, expect, it } from 'vitest';
import { NOW, expectAllow, request, world } from './helpers';
import { verifyDecisionReceipt } from '@/lib/receipts/receipts';
import { hashDocument } from '@/lib/crypto/hash';
import { TOTAL_CHECKS } from '@/lib/policy/engine';
import { recordOutcome } from '@/lib/demo/outcome';
import { verifyAttestation } from '@/lib/receipts/receipts';

describe('valid flow: Buyer Agent asks Procurement Agent for a $250 purchase', () => {
  it('ALLOWs with every predicate passing and a signed receipt', async () => {
    const w = world();
    const req = request(w, { requester: 'buyer', amount: 250 });
    const d = await w.verifier.gate(req, { now: NOW });

    expectAllow(d);
    expect(d.checks).toHaveLength(TOTAL_CHECKS);
    expect(d.checks.filter((c) => c.status === 'fail')).toHaveLength(0);
    expect(d.checks.filter((c) => c.status === 'pass').length).toBeGreaterThanOrEqual(18);
    expect(d.policyId).toBe('procurement-purchase-v1');
    expect(d.subject).toBe(w.agents.buyer.did);
    expect(d.verifier).toBe(w.agents.procurement.did);
    expect(d.requestHash).toBe(hashDocument(req));
    expect(d.evidence.credentialIds).toEqual([w.agents.buyer.credentials[0].id]);
    expect(d.evidence.grantIds).toEqual([w.agents.buyer.grants[0].id]);
    expect(d.evidence.attestationIds).toHaveLength(2);
    expect(d.evidence.issuerDids).toEqual([w.issuers.verdant.did]);

    // the receipt is signed by the verifier and bound to request + policy hashes
    const r = d.receipt!;
    expect(verifyDecisionReceipt(r).valid).toBe(true);
    expect(r.verifier).toBe(w.agents.procurement.did);
    expect(r.requestHash).toBe(d.requestHash);
    expect(r.policyHash).toBe(hashDocument(w.verifier.policy));
    expect(r.checks.map((c) => c.id)).toEqual(d.checks.map((c) => c.id));
  });

  it('a successful action earns a new signed counterparty attestation', async () => {
    const w = world();
    const before = w.agents.buyer.attestations.length;
    const req = request(w, { requester: 'buyer', amount: 250 });
    const d = await w.verifier.gate(req, { now: NOW });
    recordOutcome(w, req, d);
    expect(w.agents.buyer.attestations).toHaveLength(before + 1);
    const newest = w.agents.buyer.attestations.at(-1)!;
    expect(newest.issuer).toBe(w.agents.procurement.did);
    expect(newest.requestHash).toBe(d.requestHash);
    expect(verifyAttestation(newest).valid).toBe(true);
    expect(w.agents.buyer.history[0]).toBe(d.receipt);
  });

  it('streams checks through onCheck in stage order', async () => {
    const w = world();
    const seen: string[] = [];
    await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW, onCheck: (c) => void seen.push(c.stage) });
    const order = ['identity', 'signature', 'freshness', 'credential', 'issuer', 'revocation', 'authority', 'history', 'policy'];
    const firstIndex = order.map((s) => seen.indexOf(s));
    expect([...firstIndex].sort((a, b) => a - b)).toEqual(firstIndex);
  });
});
