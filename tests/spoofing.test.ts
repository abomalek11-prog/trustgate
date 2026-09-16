import { describe, expect, it } from 'vitest';
import { NOW, expectDeny, request, status, world } from './helpers';
import { buildActionRequest } from '@/lib/requests/build';
import { presentationFor } from '@/lib/demo/scenarios';
import { verificationMethodId } from '@/lib/identity/did-key';

describe('spoofed identity', () => {
  it('a clone with the victim DID and a copied profile is DENIED on the signature check', async () => {
    const w = world();
    // The clone builds the request exactly like the buyer, claiming the buyer's DID.
    const req = request(w, { requester: 'clone', amount: 250 });
    expect(req.from).toBe(w.agents.buyer.did);
    expect(req.presentation.credentials[0]).toEqual(w.agents.buyer.credentials[0]);
    const d = await w.verifier.gate(req, { now: NOW });
    expectDeny(d, 'REQUEST_SIGNATURE_VALID');
    // everything the clone copied still verifies — it just cannot prove key control
    expect(status(d, 'CREDENTIAL_SIGNATURE_VALID')).toBe('pass');
    expect(status(d, 'AUTHORITY_SIGNATURE_VALID')).toBe('pass');
    expect(status(d, 'AUTHORITY_AMOUNT_WITHIN_GRANT')).toBe('pass');
    expect(d.explanation).toMatch(/spoofed identity/i);
  });

  it('a clone that declares its OWN key in the proof fails identity binding', async () => {
    const w = world();
    const clone = w.agents.clone;
    const req = buildActionRequest({
      from: w.agents.buyer.did,
      signingKey: clone.keys.secretKey,
      verificationMethod: verificationMethodId(clone.did),
      to: w.agents.procurement.did,
      action: 'purchase',
      resource: 'vendor:northwind/api-credits',
      params: { amount: { value: 250, currency: 'USD' } },
      presentation: presentationFor(clone),
      now: NOW,
    });
    const d = await w.verifier.gate(req, { now: NOW });
    expectDeny(d, 'IDENTITY_RESOLVED', 'REQUEST_SIGNATURE_VALID');
  });

  it('a forged envelope does not consume the victim nonce', async () => {
    const w = world();
    const req = request(w, { requester: 'clone', amount: 250 });
    await w.verifier.gate(req, { now: NOW });
    expect(w.verifier.nonceCache.has(req.nonce)).toBe(false);
  });
});
