import { describe, expect, it } from 'vitest';
import { NOW, expectAllow, expectDeny, request, world } from './helpers';
import { setCredentialRevoked } from '@/lib/demo/world';
import { isRevoked, revokedIndices, verifyStatusList } from '@/lib/credentials/status-list';

describe('revocation via issuer-signed status list', () => {
  it('a credential that was valid is DENIED once the issuer revokes it, and ALLOWED again when restored', async () => {
    const w = world();
    const vc = w.agents.buyer.credentials[0];
    expectAllow(await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW }));

    setCredentialRevoked(w, vc, true, NOW);
    const list = w.issuers.verdant.statusList;
    expect(isRevoked(list, 42)).toBe(true);
    expect(revokedIndices(list)).toEqual([42]);
    expect(verifyStatusList(list, w.issuers.verdant.did).valid).toBe(true);

    const d = await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW });
    expectDeny(d, 'CREDENTIAL_NOT_REVOKED');
    expect(d.explanation).toMatch(/revoked/i);

    setCredentialRevoked(w, vc, false, NOW);
    expectAllow(await w.verifier.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW }));
  });

  it('fails closed when the status list is unavailable', async () => {
    const w = world();
    const { Verifier } = await import('@/lib/verifier/verifier');
    const blind = new Verifier({ did: w.agents.procurement.did, keys: w.agents.procurement.keys, policy: w.policy });
    const d = await blind.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW });
    expectDeny(d, 'CREDENTIAL_NOT_REVOKED');
    expect(d.checks.find((c) => c.id === 'CREDENTIAL_NOT_REVOKED')!.detail).toMatch(/not available/);
  });

  it('ignores a status list not signed by the credential issuer', async () => {
    const w = world();
    const { Verifier } = await import('@/lib/verifier/verifier');
    const { createStatusList } = await import('@/lib/credentials/status-list');
    // Shady publishes a list under Verdant's URL — the verifier must not accept it
    const impostor = createStatusList({ issuer: w.issuers.shady, id: w.issuers.verdant.statusListId, validFrom: NOW.toISOString() });
    const v = new Verifier({ did: w.agents.procurement.did, keys: w.agents.procurement.keys, policy: w.policy, resolveStatusList: () => impostor });
    const d = await v.gate(request(w, { requester: 'buyer', amount: 250 }), { now: NOW });
    expectDeny(d, 'CREDENTIAL_NOT_REVOKED');
    expect(d.checks.find((c) => c.id === 'CREDENTIAL_NOT_REVOKED')!.detail).toMatch(/not authentically signed/);
  });
});
