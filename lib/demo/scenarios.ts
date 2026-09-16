/**
 * Attack Lab scenarios. Each one builds a REAL signed request (or mutates the
 * world in a way a real attacker/issuer would) and runs it through the same
 * verifier the console uses. Nothing is mocked: a DENY here is the engine
 * rejecting genuine bytes.
 */
import type { CapabilityGrant } from '../authority/types';
import type { VerifiableCredential } from '../credentials/types';
import { hashDocument } from '../crypto/hash';
import type { Decision, CheckId } from '../policy/types';
import { buildActionRequest } from '../requests/build';
import type { ActionRequest, Presentation } from '../requests/types';
import type { GateContext } from '../policy/engine';
import type { AgentActor, AgentKey, DemoWorld } from './world';
import { setCredentialRevoked } from './world';

export type ScenarioId =
  | 'valid'
  | 'spoofed'
  | 'overscope'
  | 'tampered'
  | 'forged-grant'
  | 'revoked'
  | 'untrusted-issuer'
  | 'replay'
  | 'stale'
  | 'expired-grant'
  | 'no-authority'
  | 'borrowed-credential';

export type ScenarioCategory = 'identity' | 'credential' | 'authority' | 'freshness' | 'policy';

export interface Scenario {
  id: ScenarioId;
  title: string;
  category: ScenarioCategory;
  attack: boolean;
  /** what the requester/attacker does */
  description: string;
  /** which predicate catches it */
  defense: string;
  expected: 'ALLOW' | 'DENY';
  /** checks that MUST be `fail` for this scenario */
  expectedFailures: CheckId[];
  requester: AgentKey;
  amount: number;
}

export const DEFAULT_RESOURCE = 'vendor:northwind/api-credits';

export const SCENARIOS: Scenario[] = [
  {
    id: 'valid',
    title: 'Legitimate $250 purchase',
    category: 'policy',
    attack: false,
    description: 'Buyer Agent signs a fresh request with its own key and presents its Verdant credential, Acme’s $500 grant and two counterparty attestations.',
    defense: 'Every predicate passes; the verifier signs an ALLOW receipt.',
    expected: 'ALLOW',
    expectedFailures: [],
    requester: 'buyer',
    amount: 250,
  },
  {
    id: 'spoofed',
    title: 'Spoofed identity',
    category: 'identity',
    attack: true,
    description: 'A clone copies Buyer Agent’s DID, credential, grant and attestations byte-for-byte, then signs the request with its own key.',
    defense: 'REQUEST_SIGNATURE_VALID — the signature does not verify under the public key embedded in the claimed did:key.',
    expected: 'DENY',
    expectedFailures: ['REQUEST_SIGNATURE_VALID'],
    requester: 'clone',
    amount: 250,
  },
  {
    id: 'overscope',
    title: 'Over-scope amount ($2,000)',
    category: 'authority',
    attack: true,
    description: 'The genuine Buyer Agent — valid key, valid credential — asks for $2,000 when Acme only delegated $500.',
    defense: 'AUTHORITY_AMOUNT_WITHIN_GRANT — identity is not authority; the principal’s cap binds.',
    expected: 'DENY',
    expectedFailures: ['AUTHORITY_AMOUNT_WITHIN_GRANT', 'POLICY_AMOUNT_WITHIN_LIMIT'],
    requester: 'buyer',
    amount: 2000,
  },
  {
    id: 'tampered',
    title: 'Tampered credential',
    category: 'credential',
    attack: true,
    description: 'Buyer Agent edits its own credential after issuance (upgrades verificationLevel to “KYB-3 / unlimited”) and presents it, re-signing the request envelope.',
    defense: 'CREDENTIAL_SIGNATURE_VALID — the issuer’s Ed25519 proof no longer matches the canonical document.',
    expected: 'DENY',
    expectedFailures: ['CREDENTIAL_SIGNATURE_VALID'],
    requester: 'buyer',
    amount: 250,
  },
  {
    id: 'forged-grant',
    title: 'Forged authority ($5,000 cap)',
    category: 'authority',
    attack: true,
    description: 'Buyer Agent rewrites Acme’s grant to raise maxAmount from $500 to $5,000, then requests $2,000.',
    defense: 'AUTHORITY_SIGNATURE_VALID — only Acme’s key can produce a valid proof over the edited grant.',
    expected: 'DENY',
    expectedFailures: ['AUTHORITY_SIGNATURE_VALID', 'POLICY_AMOUNT_WITHIN_LIMIT'],
    requester: 'buyer',
    amount: 2000,
  },
  {
    id: 'revoked',
    title: 'Revoked credential',
    category: 'credential',
    attack: true,
    description: 'Verdant Registry revokes Buyer Agent’s credential by publishing a re-signed status list with bit 42 set. Buyer then sends a perfectly formed $250 request.',
    defense: 'CREDENTIAL_NOT_REVOKED — the verifier fetches the issuer-signed status list and sees the flag.',
    expected: 'DENY',
    expectedFailures: ['CREDENTIAL_NOT_REVOKED'],
    requester: 'buyer',
    amount: 250,
  },
  {
    id: 'untrusted-issuer',
    title: 'Untrusted issuer',
    category: 'credential',
    attack: true,
    description: 'Rogue Reseller Bot has a real key and a cryptographically valid VerifiedBusinessAgent credential — issued by Shady Certs Ltd.',
    defense: 'CREDENTIAL_ISSUER_TRUSTED — valid ≠ trusted. Add Shady Certs to the policy’s trusted issuers and watch it flip to ALLOW.',
    expected: 'DENY',
    expectedFailures: ['CREDENTIAL_ISSUER_TRUSTED'],
    requester: 'rogue',
    amount: 250,
  },
  {
    id: 'replay',
    title: 'Replayed request',
    category: 'freshness',
    attack: true,
    description: 'Buyer Agent’s valid $250 request is ALLOWED. An attacker who captured the envelope sends the identical bytes again.',
    defense: 'NONCE_UNSEEN — the verifier already consumed that nonce.',
    expected: 'DENY',
    expectedFailures: ['NONCE_UNSEEN'],
    requester: 'buyer',
    amount: 250,
  },
  {
    id: 'stale',
    title: 'Stale (captured) request',
    category: 'freshness',
    attack: true,
    description: 'A genuinely signed Buyer request issued 5 minutes ago is delivered now.',
    defense: 'REQUEST_FRESH — issuedAt is beyond the policy’s 60-second window and the envelope has expired.',
    expected: 'DENY',
    expectedFailures: ['REQUEST_FRESH'],
    requester: 'buyer',
    amount: 250,
  },
  {
    id: 'expired-grant',
    title: 'Expired delegation',
    category: 'authority',
    attack: true,
    description: 'Buyer Agent presents Acme’s H1-2026 grant (valid until 2026-06-30) instead of the current one.',
    defense: 'AUTHORITY_VALIDITY_WINDOW — delegated authority is time-boxed.',
    expected: 'DENY',
    expectedFailures: ['AUTHORITY_VALIDITY_WINDOW'],
    requester: 'buyer',
    amount: 250,
  },
  {
    id: 'no-authority',
    title: 'Identity without authority',
    category: 'authority',
    attack: true,
    description: 'Buyer Agent proves its identity and presents its credential, but no capability grant at all.',
    defense: 'AUTHORITY_PRESENT — a verified identity has zero purchasing power until a principal delegates it.',
    expected: 'DENY',
    expectedFailures: ['AUTHORITY_PRESENT'],
    requester: 'buyer',
    amount: 250,
  },
  {
    id: 'borrowed-credential',
    title: 'Borrowed credential',
    category: 'credential',
    attack: true,
    description: 'Rogue Reseller Bot presents Buyer Agent’s (perfectly valid) credential and grant, signed with Rogue’s own key.',
    defense: 'CREDENTIAL_PRESENT / AUTHORITY_PRESENT — the credential is about a different subject; the grant names a different agent.',
    expected: 'DENY',
    expectedFailures: ['CREDENTIAL_PRESENT', 'AUTHORITY_PRESENT'],
    requester: 'rogue',
    amount: 250,
  },
];

export const SCENARIO_BY_ID: Record<ScenarioId, Scenario> = Object.fromEntries(SCENARIOS.map((s) => [s.id, s])) as Record<ScenarioId, Scenario>;

export function presentationFor(agent: AgentActor): Presentation {
  return { credentials: agent.credentials, grants: agent.grants, attestations: agent.attestations };
}

export interface BuildRequestOptions {
  requester: AgentKey;
  amount: number;
  resource?: string;
  now: Date;
  presentation?: Presentation;
  /** override issuedAt (for the stale scenario) */
  issuedAt?: Date;
  ttlSeconds?: number;
  description?: string;
}

/**
 * Build a request the way the chosen agent would. A clone automatically
 * "claims" its victim's DID while signing with its own key — that is the attack.
 */
export function buildRequestFor(world: DemoWorld, o: BuildRequestOptions): ActionRequest {
  const agent = world.agents[o.requester];
  const from = agent.claimsDid ?? agent.did;
  return buildActionRequest({
    from,
    signingKey: agent.keys.secretKey,
    to: world.agents.procurement.did,
    action: 'purchase',
    resource: o.resource ?? DEFAULT_RESOURCE,
    params: {
      amount: { value: o.amount, currency: 'USD' },
      description: o.description ?? (o.amount === 250 ? '25 API credits' : 'API credits'),
    },
    presentation: o.presentation ?? presentationFor(agent),
    now: o.issuedAt ?? o.now,
    ttlSeconds: o.ttlSeconds,
  });
}

/** Deep-clone helper for building tampered evidence without touching fixtures. */
function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

export function tamperedCredential(vc: VerifiableCredential): VerifiableCredential {
  const t = clone(vc);
  t.credentialSubject.verificationLevel = 'KYB-3 / unlimited';
  return t; // proof untouched => signature no longer matches
}

export function forgedGrant(grant: CapabilityGrant, newMax = 5000): CapabilityGrant {
  const g = clone(grant);
  g.authorizationDetails[0].constraints = { ...g.authorizationDetails[0].constraints, maxAmount: { value: newMax, currency: 'USD' } };
  return g;
}

export interface ScenarioStep {
  label: string;
  request: ActionRequest;
  decision: Decision;
}

export interface ScenarioRun {
  scenario: Scenario;
  request: ActionRequest;
  decision: Decision;
  /** earlier steps (e.g. the original ALLOW before a replay) */
  priorSteps: ScenarioStep[];
  note: string;
  /** hash of the presentation actually sent (differs from fixtures when tampered) */
  requestHash: string;
}

export interface RunOptions {
  now?: Date;
  onCheck?: GateContext['onCheck'];
}

export async function runScenario(world: DemoWorld, id: ScenarioId, opts: RunOptions = {}): Promise<ScenarioRun> {
  const scenario = SCENARIO_BY_ID[id];
  const now = opts.now ?? new Date();
  const buyer = world.agents.buyer;
  const rogue = world.agents.rogue;
  const priorSteps: ScenarioStep[] = [];
  let note = '';
  let request: ActionRequest;

  switch (id) {
    case 'valid':
    case 'spoofed':
    case 'overscope':
    case 'untrusted-issuer':
      request = buildRequestFor(world, { requester: scenario.requester, amount: scenario.amount, now });
      break;
    case 'tampered':
      request = buildRequestFor(world, {
        requester: 'buyer',
        amount: 250,
        now,
        presentation: { ...presentationFor(buyer), credentials: [tamperedCredential(buyer.credentials[0])] },
      });
      note = 'credentialSubject.verificationLevel was changed from "KYB-2" to "KYB-3 / unlimited" after issuance.';
      break;
    case 'forged-grant':
      request = buildRequestFor(world, {
        requester: 'buyer',
        amount: 2000,
        now,
        presentation: { ...presentationFor(buyer), grants: [forgedGrant(buyer.grants[0])] },
      });
      note = 'authorizationDetails[0].constraints.maxAmount was rewritten from $500 to $5,000 without Acme’s key.';
      break;
    case 'revoked':
      setCredentialRevoked(world, buyer.credentials[0], true, now);
      request = buildRequestFor(world, { requester: 'buyer', amount: 250, now });
      note = 'Verdant Registry published a new signed status list with index 42 set. Use "Restore credential" to undo.';
      break;
    case 'replay': {
      const first = buildRequestFor(world, { requester: 'buyer', amount: 250, now });
      const firstDecision = await world.verifier.gate(first, { now });
      priorSteps.push({ label: 'Original request (fresh nonce)', request: first, decision: firstDecision });
      request = first; // identical bytes
      note = 'The original request was ' + firstDecision.decision + ' (' + first.nonce + '). The identical envelope is now sent a second time.';
      break;
    }
    case 'stale':
      request = buildRequestFor(world, { requester: 'buyer', amount: 250, now, issuedAt: new Date(now.getTime() - 300_000) });
      note = 'The envelope was signed 300s before delivery (policy max age 60s).';
      break;
    case 'expired-grant':
      request = buildRequestFor(world, {
        requester: 'buyer',
        amount: 250,
        now,
        presentation: { ...presentationFor(buyer), grants: [world.expiredGrant] },
      });
      break;
    case 'no-authority':
      request = buildRequestFor(world, { requester: 'buyer', amount: 250, now, presentation: { ...presentationFor(buyer), grants: [] } });
      break;
    case 'borrowed-credential':
      request = buildRequestFor(world, { requester: 'rogue', amount: 250, now, presentation: presentationFor(buyer) });
      note = 'Rogue (' + rogue.did.slice(0, 24) + '…) signed a request carrying Buyer’s credential and grant.';
      break;
  }

  const decision = await world.verifier.gate(request, { now: opts.now ?? new Date(), onCheck: opts.onCheck });
  return { scenario, request, decision, priorSteps, note, requestHash: hashDocument(request) };
}
