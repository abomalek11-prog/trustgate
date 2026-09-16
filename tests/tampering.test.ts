import { describe, expect, it } from 'vitest';
import { NOW, expectDeny, presentationFor, request, status, world } from './helpers';
import { forgedGrant, tamperedCredential } from '@/lib/demo/scenarios';
import { issueCredential } from '@/lib/credentials/issue';

describe('tampered evidence', () => {
  it('editing a credential claim after issuance breaks the issuer signature', async () => {
    const w = world();
    const buyer = w.agents.buyer;
    const vc = tamperedCredential(buyer.credentials[0]);
    expect(vc.credentialSubject.verificationLevel).toBe('KYB-3 / unlimited');
    expect(vc.proof).toEqual(buyer.credentials[0].proof); // same proof, different bytes
    const req = request(w, { requester: 'buyer', amount: 250, presentation: { ...presentationFor(buyer), credentials: [vc] } });
    const d = await w.verifier.gate(req, { now: NOW });
    expectDeny(d, 'CREDENTIAL_SIGNATURE_VALID');
    // the buyer's own envelope signature is fine — it is the ISSUER's proof that fails
    expect(status(d, 'REQUEST_SIGNATURE_VALID')).toBe('pass');
    expect(d.checks.find((c) => c.id === 'CREDENTIAL_SIGNATURE_VALID')!.evidence.code).toBe('SIGNATURE_MISMATCH');
  });

  it('raising the grant cap without the principal key breaks the grant signature', async () => {
    const w = world();
    const buyer = w.agents.buyer;
    const grant = forgedGrant(buyer.grants[0], 5000);
    const req = request(w, { requester: 'buyer', amount: 2000, presentation: { ...presentationFor(buyer), grants: [grant] } });
    const d = await w.verifier.gate(req, { now: NOW });
    expectDeny(d, 'AUTHORITY_SIGNATURE_VALID');
    expect(status(d, 'CREDENTIAL_SIGNATURE_VALID')).toBe('pass');
  });

  it('a credential signed by one issuer but declaring another is rejected', async () => {
    const w = world();
    const buyer = w.agents.buyer;
    const original = buyer.credentials[0];
    // Shady signs a credential whose `issuer` field claims to be Verdant
    const forged = issueCredential({
      issuer: { did: w.issuers.shady.did, secretKey: w.issuers.shady.keys.secretKey },
      id: original.id,
      types: ['VerifiedBusinessAgent'],
      subject: original.credentialSubject,
      validFrom: original.validFrom,
      validUntil: original.validUntil,
      status: { statusListCredential: w.issuers.verdant.statusListId, index: 42 },
    });
    forged.issuer = w.issuers.verdant.did; // lie about the issuer after signing
    const req = request(w, { requester: 'buyer', amount: 250, presentation: { ...presentationFor(buyer), credentials: [forged] } });
    const d = await w.verifier.gate(req, { now: NOW });
    expectDeny(d, 'CREDENTIAL_SIGNATURE_VALID');
  });

  it('a modified request envelope (amount changed after signing) fails the request signature', async () => {
    const w = world();
    const req = request(w, { requester: 'buyer', amount: 250 });
    const altered = { ...req, params: { ...req.params, amount: { value: 25, currency: 'USD' as const } } };
    const d = await w.verifier.gate(altered, { now: NOW });
    expectDeny(d, 'REQUEST_SIGNATURE_VALID');
  });
});
