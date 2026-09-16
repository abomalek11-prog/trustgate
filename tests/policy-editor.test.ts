import { describe, expect, it } from 'vitest';
import { NOW, expectAllow, expectDeny, request, status, world } from './helpers';
import { hashDocument } from '@/lib/crypto/hash';

describe('verifier-local policy: editing one field changes the decision', () => {
  it('lowering the verifier cap below the request amount flips ALLOW -> DENY', async () => {
    const w = world();
    expectAllow(await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW }));
    w.verifier.setPolicy({ ...w.policy, require: { ...w.policy.require, authority: { ...w.policy.require.authority, maxAmount: { value: 200, currency: 'USD' } } } });
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW });
    expectDeny(d, 'POLICY_AMOUNT_WITHIN_LIMIT');
    expect(status(d, 'AUTHORITY_AMOUNT_WITHIN_GRANT')).toBe('pass'); // the grant still allowed it; the verifier did not
  });

  it('raising the verifier cap cannot exceed what the principal delegated', async () => {
    const w = world();
    w.verifier.setPolicy({ ...w.policy, require: { ...w.policy.require, authority: { ...w.policy.require.authority, maxAmount: { value: 5000, currency: 'USD' } } } });
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 2000 }), { now: NOW });
    expectDeny(d, 'AUTHORITY_AMOUNT_WITHIN_GRANT');
    expect(status(d, 'POLICY_AMOUNT_WITHIN_LIMIT')).toBe('pass');
  });

  it('requiring at least one verified attestation denies an agent with none — and allows one with history', async () => {
    const w = world();
    w.verifier.setPolicy({
      ...w.policy,
      require: { ...w.policy.require, trustedIssuers: [w.issuers.verdant.did, w.issuers.shady.did], minVerifiedAttestations: 1 },
    });
    expectDeny(await w.verifier.gate(request(w, { requester: 'rogue', amount: 250 }), { now: NOW }), 'HISTORY_ATTESTATIONS_VERIFIED');
    expectAllow(await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW }));
  });

  it('shortening the freshness window makes a 45-second-old request stale', async () => {
    const w = world();
    const req = request(w, { requester: 'buyer', amount: 250, issuedAt: new Date(NOW.getTime() - 45_000) });
    expectAllow(await w.verifier.gate(req, { now: NOW, dryRun: true }));
    w.verifier.setPolicy({ ...w.policy, require: { ...w.policy.require, requestMaxAgeSeconds: 30 } });
    expectDeny(await w.verifier.gate(req, { now: NOW }), 'REQUEST_FRESH');
  });

  it('the decision records the hash of the exact policy that produced it', async () => {
    const w = world();
    const d1 = await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW });
    expect(d1.policyHash).toBe(hashDocument(w.policy));
    const edited = { ...w.policy, version: 2, require: { ...w.policy.require, requestMaxAgeSeconds: 120 } };
    w.verifier.setPolicy(edited);
    const d2 = await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW });
    expect(d2.policyHash).toBe(hashDocument(edited));
    expect(d2.policyHash).not.toBe(d1.policyHash);
    expect(d2.receipt!.policyHash).toBe(d2.policyHash);
  });
});
