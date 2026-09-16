/**
 * The demo world: a handful of deterministic actors and the signed evidence
 * that ties them together. Everything here is REAL signed data produced by the
 * same engine the verifier uses; nothing is mocked.
 *
 *   Verdant Business Registry (trusted issuer)  ─┐
 *   Shady Certs Ltd (untrusted issuer)          ─┤ issue VerifiedBusinessAgent VCs
 *   Acme Corp Treasury (principal)  ── delegates $500 purchase authority ──▶ Buyer Agent
 *   Northwind Procurement Agent (verifier) ── attests past purchase ──▶ Buyer Agent
 *   Contoso Data Marketplace (counterparty) ── attests past purchase ──▶ Buyer Agent
 *   Spoofed Buyer (attacker) — copies Buyer's public profile, has a different key
 *   Rogue Reseller Bot — legit key, credential from the untrusted issuer
 */
import { issueGrant } from '../authority/grant';
import type { CapabilityGrant } from '../authority/types';
import { issueCredential } from '../credentials/issue';
import { createStatusList, setRevoked } from '../credentials/status-list';
import type { StatusListCredential, VerifiableCredential } from '../credentials/types';
import { VERIFIED_BUSINESS_AGENT } from '../credentials/types';
import { fingerprint } from '../crypto/hash';
import type { Policy } from '../policy/types';
import { issueAttestation } from '../receipts/receipts';
import type { Attestation, DecisionReceipt } from '../receipts/types';
import type { DID, KeyPair } from '../types';
import { Verifier } from '../verifier/verifier';
import { demoIdentity, demoUuid, FIXTURE_EPOCH } from './seeds';

export type ActorRole = 'issuer' | 'principal' | 'agent' | 'verifier' | 'counterparty';

export interface Actor {
  key: string;
  name: string;
  org: string;
  role: ActorRole;
  description: string;
  did: DID;
  keys: KeyPair;
  /** same bytes as keys.secretKey — lets an Actor be used directly as a Signer */
  secretKey: Uint8Array;
}

export interface IssuerActor extends Actor {
  role: 'issuer';
  statusListId: string;
  statusList: StatusListCredential;
}

export type AgentKind = 'buyer' | 'verifier' | 'clone' | 'rogue';

export interface AgentActor extends Actor {
  kind: AgentKind;
  /** For a spoofing clone: the DID it CLAIMS (the victim's), which differs from `did` */
  claimsDid?: DID;
  controller?: DID;
  credentials: VerifiableCredential[];
  grants: CapabilityGrant[];
  attestations: Attestation[];
  /** signed receipts this agent has accumulated (grows with each ALLOW) */
  history: DecisionReceipt[];
  riskFlags: string[];
}

export const AGENT_KEYS = ['buyer', 'procurement', 'clone', 'rogue'] as const;
export type AgentKey = (typeof AGENT_KEYS)[number];

export interface DemoWorld {
  issuers: { verdant: IssuerActor; shady: IssuerActor };
  principals: { acme: Actor; rogueHoldings: Actor };
  counterparties: { contoso: Actor };
  agents: Record<AgentKey, AgentActor>;
  /** the fixture grant that has already expired (used by the expired-authority scenario) */
  expiredGrant: CapabilityGrant;
  verifier: Verifier;
  policy: Policy;
}

function actor(key: string, name: string, org: string, role: ActorRole, description: string): Actor {
  const { did, keys } = demoIdentity(key);
  return { key, name, org, role, description, did, keys, secretKey: keys.secretKey };
}

export function defaultPolicy(trustedIssuer: DID): Policy {
  return {
    policyId: 'procurement-purchase-v1',
    version: 1,
    description: 'Northwind Procurement Agent — who may ask us to execute a purchase, and within what limits.',
    action: 'purchase',
    require: {
      identityProof: true,
      audienceMatch: true,
      requestMaxAgeSeconds: 60,
      rejectReusedNonce: true,
      credentialTypes: [VERIFIED_BUSINESS_AGENT],
      trustedIssuers: [trustedIssuer],
      notRevoked: true,
      authority: {
        action: 'purchase',
        maxAmount: { value: 500, currency: 'USD' },
        principalMustBeCredentialController: true,
      },
      minVerifiedAttestations: 0,
    },
  };
}

export function createDemoWorld(): DemoWorld {
  // ── Issuers ─────────────────────────────────────────────────────────
  const verdantBase = actor('issuer:verdant', 'Verdant Business Registry', 'Verdant Registry Inc.', 'issuer', 'Trusted KYB registry. Issues VerifiedBusinessAgent credentials after verifying the controlling business.');
  const shadyBase = actor('issuer:shady', 'Shady Certs Ltd', 'Shady Certs Ltd', 'issuer', 'Issues credentials to anyone who pays. Signatures are cryptographically valid — the verifier simply does not trust them.');
  const verdant: IssuerActor = {
    ...verdantBase,
    role: 'issuer',
    statusListId: 'https://verdant.example/status/1',
    statusList: createStatusList({ issuer: verdantBase, id: 'https://verdant.example/status/1', validFrom: FIXTURE_EPOCH }),
  };
  const shady: IssuerActor = {
    ...shadyBase,
    role: 'issuer',
    statusListId: 'https://shadycerts.example/status/1',
    statusList: createStatusList({ issuer: shadyBase, id: 'https://shadycerts.example/status/1', validFrom: FIXTURE_EPOCH }),
  };

  // ── Principals & counterparties ─────────────────────────────────────
  const acme = actor('principal:acme', 'Acme Corp Treasury', 'Acme Corp', 'principal', 'The business that owns the Buyer Agent and is on the hook for what it buys. Delegates scoped purchasing authority.');
  const rogueHoldings = actor('principal:rogue-holdings', 'Rogue Holdings', 'Rogue Holdings LLC', 'principal', 'Owner of the Rogue Reseller Bot.');
  const contoso = actor('counterparty:contoso', 'Contoso Data Marketplace', 'Contoso', 'counterparty', 'A past counterparty that signed an attestation about the Buyer Agent.');

  // ── Agents ──────────────────────────────────────────────────────────
  const buyerBase = actor('agent:buyer', 'Buyer Agent', 'Acme Corp', 'agent', 'Acme’s purchasing agent. Key-bound identity, issuer-verified business credential, $500 delegated purchase authority, signed history.');
  const procurementBase = actor('agent:procurement', 'Procurement Agent', 'Northwind Cloud', 'verifier', 'Northwind’s selling/procurement gateway. Runs TrustGate on every incoming request before executing a purchase.');
  const cloneBase = actor('agent:clone', 'Spoofed Buyer Agent', 'unknown', 'agent', 'An attacker that copied the Buyer Agent’s public profile (DID, credential, grant) but does not hold the Buyer’s private key.');
  const rogueBase = actor('agent:rogue', 'Rogue Reseller Bot', 'Rogue Holdings LLC', 'agent', 'A real agent with a real key and a cryptographically valid credential — from an issuer this verifier does not trust.');

  const buyerVc = issueCredential({
    issuer: verdant,
    id: demoUuid('vc:buyer:verdant'),
    types: [VERIFIED_BUSINESS_AGENT],
    subject: {
      id: buyerBase.did,
      controller: acme.did,
      businessName: 'Acme Corp',
      jurisdiction: 'US-DE',
      businessVerified: true,
      verificationLevel: 'KYB-2',
    },
    validFrom: FIXTURE_EPOCH,
    validUntil: '2027-09-01T00:00:00Z',
    status: { statusListCredential: verdant.statusListId, index: 42 },
  });

  const rogueVc = issueCredential({
    issuer: shady,
    id: demoUuid('vc:rogue:shady'),
    types: [VERIFIED_BUSINESS_AGENT],
    subject: {
      id: rogueBase.did,
      controller: rogueHoldings.did,
      businessName: 'Rogue Holdings LLC',
      jurisdiction: 'XX',
      businessVerified: true,
      verificationLevel: 'self-declared',
    },
    validFrom: FIXTURE_EPOCH,
    validUntil: '2027-09-01T00:00:00Z',
    status: { statusListCredential: shady.statusListId, index: 7 },
  });

  const buyerGrant = issueGrant({
    principal: acme,
    agent: buyerBase.did,
    id: demoUuid('grant:acme:buyer:2026q3'),
    authorizationDetails: [
      { type: 'purchase', actions: ['purchase'], locations: ['vendor:*'], constraints: { maxAmount: { value: 500, currency: 'USD' } } },
    ],
    validFrom: FIXTURE_EPOCH,
    validUntil: '2027-03-31T23:59:59Z',
    nonce: demoUuid('grant-nonce:acme:buyer:2026q3').slice(9, 23),
  });

  const expiredGrant = issueGrant({
    principal: acme,
    agent: buyerBase.did,
    id: demoUuid('grant:acme:buyer:2026h1'),
    authorizationDetails: [
      { type: 'purchase', actions: ['purchase'], locations: ['vendor:*'], constraints: { maxAmount: { value: 500, currency: 'USD' } } },
    ],
    validFrom: '2026-01-01T00:00:00Z',
    validUntil: '2026-06-30T23:59:59Z',
    nonce: demoUuid('grant-nonce:acme:buyer:2026h1').slice(9, 23),
  });

  const rogueGrant = issueGrant({
    principal: rogueHoldings,
    agent: rogueBase.did,
    id: demoUuid('grant:rogue-holdings:rogue'),
    authorizationDetails: [
      { type: 'purchase', actions: ['purchase'], locations: ['vendor:*'], constraints: { maxAmount: { value: 500, currency: 'USD' } } },
    ],
    validFrom: FIXTURE_EPOCH,
    validUntil: '2027-03-31T23:59:59Z',
    nonce: demoUuid('grant-nonce:rogue').slice(9, 23),
  });

  const buyerAttestations: Attestation[] = [
    issueAttestation({
      attester: procurementBase,
      id: demoUuid('att:northwind:buyer:1'),
      subject: buyerBase.did,
      action: 'purchase',
      resource: 'vendor:northwind/api-credits',
      amount: { value: 120, currency: 'USD' },
      outcome: 'completed',
      observedAt: '2026-08-12T09:14:00Z',
      statement: 'Buyer Agent completed a $120 API-credit purchase; payment settled within SLA.',
    }),
    issueAttestation({
      attester: contoso,
      id: demoUuid('att:contoso:buyer:1'),
      subject: buyerBase.did,
      action: 'purchase',
      resource: 'vendor:contoso/dataset-license',
      amount: { value: 340, currency: 'USD' },
      outcome: 'completed',
      observedAt: '2026-08-27T15:42:00Z',
      statement: 'Buyer Agent licensed a dataset for $340; no disputes.',
    }),
  ];

  const buyer: AgentActor = {
    ...buyerBase,
    kind: 'buyer',
    controller: acme.did,
    credentials: [buyerVc],
    grants: [buyerGrant],
    attestations: buyerAttestations,
    history: [],
    riskFlags: [],
  };

  const procurement: AgentActor = {
    ...procurementBase,
    kind: 'verifier',
    credentials: [],
    grants: [],
    attestations: [],
    history: [],
    riskFlags: [],
  };

  // The clone copies everything PUBLIC about the buyer. It cannot copy the private key.
  const clone: AgentActor = {
    ...cloneBase,
    kind: 'clone',
    claimsDid: buyer.did,
    controller: acme.did,
    credentials: [buyerVc],
    grants: [buyerGrant],
    attestations: buyerAttestations,
    history: [],
    riskFlags: [
      'Claims DID ' + buyer.did.slice(0, 20) + '… but its actual key fingerprint is ' + fingerprint(cloneBase.keys.publicKey) + ' (mismatch)',
      'Cannot produce signatures that verify under the claimed DID',
    ],
  };

  const rogue: AgentActor = {
    ...rogueBase,
    kind: 'rogue',
    controller: rogueHoldings.did,
    credentials: [rogueVc],
    grants: [rogueGrant],
    attestations: [],
    history: [],
    riskFlags: ['Credential issuer (Shady Certs Ltd) is not in the verifier’s trusted-issuer list', 'No verified counterparty attestations'],
  };

  const policy = defaultPolicy(verdant.did);
  const issuers = { verdant, shady };
  const labels: Record<DID, string> = Object.fromEntries(
    [verdant, shady, acme, rogueHoldings, contoso, buyer, procurement, clone, rogue].map((a) => [a.did, a.name]),
  );
  const verifier = new Verifier({
    did: procurement.did,
    keys: procurement.keys,
    policy,
    labels,
    // "Fetch" the issuer's CURRENT published status list on every check.
    resolveStatusList: (id) => Object.values(issuers).find((i) => i.statusListId === id)?.statusList,
  });

  return {
    issuers,
    principals: { acme, rogueHoldings },
    counterparties: { contoso },
    agents: { buyer, procurement, clone, rogue },
    expiredGrant,
    verifier,
    policy,
  };
}

/** Issuer revokes (or restores) a credential by re-signing its status list. */
export function setCredentialRevoked(world: DemoWorld, vc: VerifiableCredential, revoked: boolean, now = new Date()): void {
  const issuer = Object.values(world.issuers).find((i) => i.did === vc.issuer);
  if (!issuer || !vc.credentialStatus) throw new Error('Unknown issuer or credential has no status entry');
  issuer.statusList = setRevoked(issuer.statusList, issuer, Number(vc.credentialStatus.statusListIndex), revoked, now.toISOString());
}

export function findAgentByDid(world: DemoWorld, did: DID): AgentActor | undefined {
  return Object.values(world.agents).find((a) => a.did === did);
}

export function actorName(world: DemoWorld, did: DID): string {
  const all: Actor[] = [
    ...Object.values(world.issuers),
    ...Object.values(world.principals),
    ...Object.values(world.counterparties),
    ...Object.values(world.agents),
  ];
  return all.find((a) => a.did === did)?.name ?? did;
}

export function allActors(world: DemoWorld): Actor[] {
  return [
    ...Object.values(world.agents),
    ...Object.values(world.issuers),
    ...Object.values(world.principals),
    ...Object.values(world.counterparties),
  ];
}
