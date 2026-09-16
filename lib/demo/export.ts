/**
 * Public, serializable view of the demo world — what an API or a seed file
 * exposes. Secret keys never leave the actor objects.
 */
import { fingerprint } from '../crypto/hash';
import { resolveDidKey } from '../identity/did-key';
import type { DemoWorld, AgentActor, Actor } from './world';
import { allActors } from './world';
import { revokedIndices } from '../credentials/status-list';

export interface PublicActor {
  key: string;
  name: string;
  org: string;
  role: Actor['role'];
  description: string;
  did: string;
  keyFingerprint: string;
  publicKeyMultibase: string;
}

export interface PublicAgent extends PublicActor {
  /** URL-friendly id: buyer | procurement | clone | rogue */
  slug: string;
  kind: AgentActor['kind'];
  claimsDid?: string;
  controller?: string;
  credentials: AgentActor['credentials'];
  grants: AgentActor['grants'];
  attestations: AgentActor['attestations'];
  history: AgentActor['history'];
  riskFlags: string[];
}

export function publicActor(a: Actor): PublicActor {
  return {
    key: a.key,
    name: a.name,
    org: a.org,
    role: a.role,
    description: a.description,
    did: a.did,
    keyFingerprint: fingerprint(a.keys.publicKey),
    publicKeyMultibase: resolveDidKey(a.did)?.document.verificationMethod[0].publicKeyMultibase ?? '',
  };
}

export function publicAgent(a: AgentActor): PublicAgent {
  return {
    ...publicActor(a),
    slug: a.key.replace(/^agent:/, ''),
    kind: a.kind,
    ...(a.claimsDid ? { claimsDid: a.claimsDid } : {}),
    ...(a.controller ? { controller: a.controller } : {}),
    credentials: a.credentials,
    grants: a.grants,
    attestations: a.attestations,
    history: a.history,
    riskFlags: a.riskFlags,
  };
}

export function exportWorld(world: DemoWorld) {
  return {
    _note: 'SYNTHETIC DEMO FIXTURES. Keys derive from SHA-256("trustgate-demo-v1:" + label); nothing here is secret. See lib/demo/seeds.ts.',
    generatedFrom: 'lib/demo/world.ts',
    fixtureEpoch: '2026-09-01T00:00:00Z',
    actors: allActors(world).map(publicActor),
    agents: Object.fromEntries(Object.entries(world.agents).map(([k, a]) => [k, publicAgent(a)])),
    issuers: Object.fromEntries(
      Object.entries(world.issuers).map(([k, i]) => [k, { ...publicActor(i), statusListId: i.statusListId, statusList: i.statusList, revoked: revokedIndices(i.statusList) }]),
    ),
    expiredGrant: world.expiredGrant,
    policy: world.policy,
  };
}
