import { describe, expect, it } from 'vitest';
import { NOW, expectAllow, expectDeny, presentationFor, request, status, world } from './helpers';

describe('scoped authority', () => {
  it('a genuine agent asking for $2,000 against a $500 grant is DENIED on amount — identity and credential still pass', async () => {
    const w = world();
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 2000 }), { now: NOW });
    expectDeny(d, 'AUTHORITY_AMOUNT_WITHIN_GRANT', 'POLICY_AMOUNT_WITHIN_LIMIT');
    expect(status(d, 'REQUEST_SIGNATURE_VALID')).toBe('pass');
    expect(status(d, 'CREDENTIAL_SIGNATURE_VALID')).toBe('pass');
    expect(status(d, 'CREDENTIAL_NOT_REVOKED')).toBe('pass');
    expect(status(d, 'AUTHORITY_SIGNATURE_VALID')).toBe('pass');
    expect(d.explanation).toMatch(/Valid identity does not mean unlimited authority/);
  });

  it('exactly the cap is allowed; one dollar more is not', async () => {
    const w = world();
    expectAllow(await w.verifier.gate(request(w, { requester: 'buyer', amount: 500 }), { now: NOW }));
    expectDeny(await w.verifier.gate(request(w, { requester: 'buyer', amount: 501 }), { now: NOW }), 'AUTHORITY_AMOUNT_WITHIN_GRANT');
  });

  it('a resource outside the grant locations is DENIED', async () => {
    const w = world();
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 100, resource: 'payroll:transfer' }), { now: NOW });
    expectDeny(d, 'AUTHORITY_RESOURCE_MATCH');
  });

  it('an action the principal never delegated is DENIED', async () => {
    const w = world();
    const req = request(w, { requester: 'buyer', amount: 100 });
    // sign a request for a different action with the buyer's real key
    const { buildActionRequest } = await import('@/lib/requests/build');
    const transfer = buildActionRequest({
      from: w.agents.buyer.did,
      signingKey: w.agents.buyer.keys.secretKey,
      to: req.to,
      action: 'transfer',
      resource: 'vendor:northwind/wallet',
      params: { amount: { value: 100, currency: 'USD' } },
      presentation: presentationFor(w.agents.buyer),
      now: NOW,
    });
    const d = await w.verifier.gate(transfer, { now: NOW });
    expect(d.allow).toBe(false);
    expect(status(d, 'AUTHORITY_ACTION_MATCH')).toBe('fail');
  });

  it('identity without any grant is DENIED (authority is separate from identity)', async () => {
    const w = world();
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 10, presentation: { ...presentationFor(w.agents.buyer), grants: [] } }), { now: NOW });
    expectDeny(d, 'AUTHORITY_PRESENT');
    expect(status(d, 'CREDENTIAL_ISSUER_TRUSTED')).toBe('pass');
  });

  it('a grant from a principal other than the attested controller is DENIED', async () => {
    const w = world();
    const { issueGrant } = await import('@/lib/authority/grant');
    const rogueGrant = issueGrant({
      principal: w.principals.rogueHoldings,
      agent: w.agents.buyer.did,
      id: 'urn:uuid:test-rogue-grant',
      authorizationDetails: [{ type: 'purchase', actions: ['purchase'], locations: ['vendor:*'], constraints: { maxAmount: { value: 9999, currency: 'USD' } } }],
      validFrom: '2026-09-01T00:00:00Z',
      validUntil: '2027-09-01T00:00:00Z',
      nonce: 'n1',
    });
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 250, presentation: { ...presentationFor(w.agents.buyer), grants: [rogueGrant] } }), { now: NOW });
    expectDeny(d, 'AUTHORITY_PRINCIPAL_BOUND');
    expect(status(d, 'AUTHORITY_SIGNATURE_VALID')).toBe('pass');
  });
});
