import { describe, expect, it } from 'vitest';
import { NOW, expectAllow, expectDeny, request, status, world } from './helpers';

describe('replay protection', () => {
  it('the identical envelope sent twice is ALLOWED once and then DENIED on nonce reuse', async () => {
    const w = world();
    const req = request(w, { requester: 'buyer', amount: 250 });
    expectAllow(await w.verifier.gate(req, { now: NOW }));
    const replay = await w.verifier.gate(req, { now: new Date(NOW.getTime() + 5_000) });
    expectDeny(replay, 'NONCE_UNSEEN');
    expect(status(replay, 'REQUEST_SIGNATURE_VALID')).toBe('pass');
    expect(status(replay, 'REQUEST_FRESH')).toBe('pass'); // still fresh — the nonce alone catches it
    expect(replay.explanation).toMatch(/Replay rejected/);
  });

  it('a request older than the policy window is DENIED as stale even with a new nonce', async () => {
    const w = world();
    const captured = request(w, { requester: 'buyer', amount: 250, issuedAt: new Date(NOW.getTime() - 300_000) });
    const d = await w.verifier.gate(captured, { now: NOW });
    expectDeny(d, 'REQUEST_FRESH');
    expect(status(d, 'NONCE_UNSEEN')).toBe('pass');
  });

  it('a request "from the future" beyond clock skew is DENIED', async () => {
    const w = world();
    const future = request(w, { requester: 'buyer', amount: 250, issuedAt: new Date(NOW.getTime() + 120_000) });
    expectDeny(await w.verifier.gate(future, { now: NOW }), 'REQUEST_FRESH');
  });

  it('two different fresh requests with different nonces are both ALLOWED', async () => {
    const w = world();
    const a = request(w, { requester: 'buyer', amount: 250 });
    const b = request(w, { requester: 'buyer', amount: 250 });
    expect(a.nonce).not.toBe(b.nonce);
    expectAllow(await w.verifier.gate(a, { now: NOW }));
    expectAllow(await w.verifier.gate(b, { now: NOW }));
  });

  it('dry-run evaluation does not consume the nonce', async () => {
    const w = world();
    const req = request(w, { requester: 'buyer', amount: 250 });
    expectAllow(await w.verifier.gate(req, { now: NOW, dryRun: true }));
    expectAllow(await w.verifier.gate(req, { now: NOW }));
  });
});
