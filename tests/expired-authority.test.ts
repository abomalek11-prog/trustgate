import { describe, expect, it } from 'vitest';
import { NOW, expectAllow, expectDeny, presentationFor, request, status, world } from './helpers';

describe('temporal constraints', () => {
  it('an expired capability grant is DENIED even though its signature is valid', async () => {
    const w = world();
    const d = await w.verifier.gate(
      request(w, { requester: 'buyer', amount: 250, presentation: { ...presentationFor(w.agents.buyer), grants: [w.expiredGrant] } }),
      { now: NOW },
    );
    expectDeny(d, 'AUTHORITY_VALIDITY_WINDOW');
    expect(status(d, 'AUTHORITY_SIGNATURE_VALID')).toBe('pass');
    expect(d.explanation).toMatch(/expired/i);
  });

  it('the same grant was valid inside its window', async () => {
    const w = world();
    const then = new Date('2026-03-15T00:00:00Z');
    // the fixture credential is only valid from 2026-09-01, so evaluate the grant alone via the engine
    const req = request(w, { requester: 'buyer', amount: 250, now: then, presentation: { ...presentationFor(w.agents.buyer), grants: [w.expiredGrant] } });
    const d = await w.verifier.gate(req, { now: then });
    expect(status(d, 'AUTHORITY_VALIDITY_WINDOW')).toBe('pass');
    expect(status(d, 'CREDENTIAL_VALIDITY_WINDOW')).toBe('fail'); // credential not yet valid on that date
  });

  it('an expired credential is DENIED', async () => {
    const w = world();
    const later = new Date('2028-01-01T00:00:00Z');
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 250, now: later }), { now: later });
    expectDeny(d, 'CREDENTIAL_VALIDITY_WINDOW');
  });

  it('the current grant is ALLOWED today', async () => {
    const w = world();
    expectAllow(await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW }));
  });
});
