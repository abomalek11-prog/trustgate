/**
 * Determinism: the committed fixture file must be exactly what the engine
 * regenerates. If this fails, run `npm run seed` and commit the result.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createDemoWorld } from '@/lib/demo/world';
import { exportWorld } from '@/lib/demo/export';
import { verifyCredentialProof } from '@/lib/credentials/verify';
import { verifyGrantProof } from '@/lib/authority/grant';
import { verifyAttestation } from '@/lib/receipts/receipts';
import { verifyStatusList } from '@/lib/credentials/status-list';

describe('deterministic demo fixtures', () => {
  const committed = JSON.parse(readFileSync(new URL('../data/demo-fixtures.json', import.meta.url), 'utf8'));
  const fresh = JSON.parse(JSON.stringify(exportWorld(createDemoWorld())));

  it('regenerate byte-for-byte identical to data/demo-fixtures.json', () => {
    expect(fresh).toEqual(committed);
  });

  it('contain no secret key material', () => {
    const text = JSON.stringify(committed);
    expect(text).not.toMatch(/secretKey/);
    expect(text).not.toMatch(/privateKey/);
    expect(committed._note).toMatch(/SYNTHETIC/);
  });

  it('every committed signed artifact verifies', () => {
    for (const agent of Object.values(committed.agents) as Array<{ credentials: never[]; grants: never[]; attestations: never[] }>) {
      for (const vc of agent.credentials) expect(verifyCredentialProof(vc).valid).toBe(true);
      for (const g of agent.grants) expect(verifyGrantProof(g).valid).toBe(true);
      for (const a of agent.attestations) expect(verifyAttestation(a).valid).toBe(true);
    }
    for (const issuer of Object.values(committed.issuers) as Array<{ did: string; statusList: never }>) {
      expect(verifyStatusList(issuer.statusList, issuer.did).valid).toBe(true);
    }
    expect(verifyGrantProof(committed.expiredGrant).valid).toBe(true);
  });

  it('the spoofed clone claims the buyer DID but has a different key', () => {
    expect(committed.agents.clone.claimsDid).toBe(committed.agents.buyer.did);
    expect(committed.agents.clone.did).not.toBe(committed.agents.buyer.did);
    expect(committed.agents.clone.keyFingerprint).not.toBe(committed.agents.buyer.keyFingerprint);
  });
});
