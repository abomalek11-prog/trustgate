/**
 * The non-negotiable principle: reputation is evidence, never a bypass.
 * An agent with a mountain of verified attestations still fails if identity,
 * credential, revocation, or authority fails.
 */
import { describe, expect, it } from 'vitest';
import { NOW, expectDeny, presentationFor, request, status, world } from './helpers';
import { issueAttestation } from '@/lib/receipts/receipts';
import { setCredentialRevoked } from '@/lib/demo/world';
import type { Attestation } from '@/lib/receipts/types';

function pileOfAttestations(w: ReturnType<typeof world>, subject: string, n: number): Attestation[] {
  const attesters = [w.agents.procurement, w.counterparties.contoso, w.principals.acme];
  return Array.from({ length: n }, (_, i) =>
    issueAttestation({
      attester: attesters[i % attesters.length],
      id: 'urn:uuid:pile-' + i,
      subject,
      action: 'purchase',
      outcome: 'completed',
      amount: { value: 100 + i, currency: 'USD' },
      observedAt: '2026-08-0' + ((i % 9) + 1) + 'T00:00:00Z',
      statement: 'Completed purchase #' + i,
    }),
  );
}

describe('reputation cannot bypass verification', () => {
  it('50 verified attestations do not rescue a spoofed identity', async () => {
    const w = world();
    const pile = pileOfAttestations(w, w.agents.buyer.did, 50);
    const d = await w.verifier.gate(request(w, { requester: 'clone', amount: 250, presentation: { ...presentationFor(w.agents.clone), attestations: pile } }), { now: NOW });
    expectDeny(d, 'REQUEST_SIGNATURE_VALID');
    expect(d.checks.find((c) => c.id === 'HISTORY_ATTESTATIONS_VERIFIED')!.detail).toMatch(/^50 of 50/);
  });

  it('50 verified attestations do not rescue a revoked credential', async () => {
    const w = world();
    setCredentialRevoked(w, w.agents.buyer.credentials[0], true, NOW);
    const pile = pileOfAttestations(w, w.agents.buyer.did, 50);
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 250, presentation: { ...presentationFor(w.agents.buyer), attestations: pile } }), { now: NOW });
    expectDeny(d, 'CREDENTIAL_NOT_REVOKED');
    expect(status(d, 'HISTORY_ATTESTATIONS_VERIFIED')).toBe('pass');
  });

  it('50 verified attestations do not rescue an over-scope amount', async () => {
    const w = world();
    const pile = pileOfAttestations(w, w.agents.buyer.did, 50);
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 2000, presentation: { ...presentationFor(w.agents.buyer), attestations: pile } }), { now: NOW });
    expectDeny(d, 'AUTHORITY_AMOUNT_WITHIN_GRANT');
  });

  it('self-attestations and attestations about someone else are not counted', async () => {
    const w = world();
    const buyer = w.agents.buyer;
    const self = issueAttestation({ attester: buyer, id: 'urn:uuid:self', subject: buyer.did, action: 'purchase', outcome: 'completed', observedAt: '2026-08-01T00:00:00Z', statement: 'I am great' });
    const aboutRogue = issueAttestation({ attester: w.counterparties.contoso, id: 'urn:uuid:other', subject: w.agents.rogue.did, action: 'purchase', outcome: 'completed', observedAt: '2026-08-01T00:00:00Z', statement: 'Rogue did fine' });
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 250, presentation: { ...presentationFor(buyer), attestations: [self, aboutRogue] } }), { now: NOW });
    expect(d.checks.find((c) => c.id === 'HISTORY_ATTESTATIONS_VERIFIED')!.detail).toMatch(/^0 of 2/);
  });

  it('a forged attestation is detected and reported, not silently counted', async () => {
    const w = world();
    const good = w.agents.buyer.attestations[0];
    const forged = { ...good, amount: { value: 999999, currency: 'USD' as const } };
    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 250, presentation: { ...presentationFor(w.agents.buyer), attestations: [forged, w.agents.buyer.attestations[1]] } }), { now: NOW });
    const h = d.checks.find((c) => c.id === 'HISTORY_ATTESTATIONS_VERIFIED')!;
    expect(h.detail).toMatch(/^1 of 2/);
    expect(h.detail).toMatch(/1 failed signature verification/);
    expect(h.status).toBe('warn');
  });
});
