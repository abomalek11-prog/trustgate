import { describe, expect, it } from 'vitest';
import { NOW, expectAllow, expectDeny, request, status, world } from './helpers';
import { verifyCredentialProof } from '@/lib/credentials/verify';

describe('untrusted issuer', () => {
  it('a cryptographically valid credential from an untrusted issuer is DENIED', async () => {
    const w = world();
    const rogueVc = w.agents.rogue.credentials[0];
    expect(verifyCredentialProof(rogueVc).valid).toBe(true); // valid ≠ trusted
    const d = await w.verifier.gate(request(w, { requester: 'rogue', amount: 250 }), { now: NOW });
    expectDeny(d, 'CREDENTIAL_ISSUER_TRUSTED');
    expect(status(d, 'CREDENTIAL_SIGNATURE_VALID')).toBe('pass');
    expect(status(d, 'REQUEST_SIGNATURE_VALID')).toBe('pass');
    expect(d.explanation).toMatch(/Valid ≠ trusted/);
  });

  it('becomes ALLOW once the verifier chooses to trust that issuer (verifier-local policy)', async () => {
    const w = world();
    w.verifier.setPolicy({
      ...w.policy,
      require: { ...w.policy.require, trustedIssuers: [...w.policy.require.trustedIssuers, w.issuers.shady.did] },
    });
    expectAllow(await w.verifier.gate(request(w, { requester: 'rogue', amount: 250 }), { now: NOW }));
  });

  it('removing the trusted issuer flips the legitimate buyer to DENY', async () => {
    const w = world();
    w.verifier.setPolicy({ ...w.policy, require: { ...w.policy.require, trustedIssuers: [] } });
    expectDeny(await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW }), 'CREDENTIAL_ISSUER_TRUSTED');
  });
});
