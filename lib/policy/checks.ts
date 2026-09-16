import type { CheckId, Stage } from './types';

export interface CheckMeta {
  stage: Stage;
  title: string;
  /** short, jargon-free explanation shown as a tooltip */
  help: string;
}

/**
 * Fixed evaluation order. The trace in the UI renders these stages:
 * identity -> signature -> freshness -> credential -> issuer -> revocation -> authority -> history -> policy
 */
export const CHECK_META: Record<CheckId, CheckMeta> = {
  IDENTITY_RESOLVED: {
    stage: 'identity',
    title: 'Identity resolves to a key',
    help: 'The requester’s did:key contains its own Ed25519 public key, and the proof names that exact key. No registry lookup is needed.',
  },
  REQUEST_AUDIENCE_MATCH: {
    stage: 'identity',
    title: 'Request addressed to this verifier',
    help: 'The request names this agent as the recipient, so a message meant for someone else cannot be forwarded here.',
  },
  REQUEST_SIGNATURE_VALID: {
    stage: 'signature',
    title: 'Request signature verifies',
    help: 'The Ed25519 signature over the canonical (JCS) request must verify under the key inside the requester’s DID. Only the private-key holder can produce it.',
  },
  REQUEST_FRESH: {
    stage: 'freshness',
    title: 'Request is fresh',
    help: 'issuedAt must be within the policy’s max age and before expiresAt. Old captured requests cannot be replayed later.',
  },
  NONCE_UNSEEN: {
    stage: 'freshness',
    title: 'Nonce not seen before',
    help: 'Each request carries a random nonce. The verifier remembers consumed nonces, so an identical envelope sent twice is rejected.',
  },
  CREDENTIAL_PRESENT: {
    stage: 'credential',
    title: 'Required credential presented',
    help: 'The policy names credential types the requester must hold, and the credential must be ABOUT the requester (subject id = from).',
  },
  CREDENTIAL_SIGNATURE_VALID: {
    stage: 'credential',
    title: 'Credential signature verifies',
    help: 'The issuer’s Ed25519 proof over the credential must verify. Editing any field after issuance — a claim, a date, the subject — breaks it.',
  },
  CREDENTIAL_VALIDITY_WINDOW: {
    stage: 'credential',
    title: 'Credential within validity window',
    help: 'now must be between validFrom and validUntil.',
  },
  CREDENTIAL_ISSUER_TRUSTED: {
    stage: 'issuer',
    title: 'Issuer is trusted by this verifier',
    help: 'A perfectly valid signature from an issuer this verifier does not trust proves nothing. Trust in issuers is a local policy choice.',
  },
  CREDENTIAL_NOT_REVOKED: {
    stage: 'revocation',
    title: 'Credential not revoked',
    help: 'The issuer publishes a signed status list; the credential’s index must not be flagged. An unavailable or unsigned list fails closed.',
  },
  AUTHORITY_PRESENT: {
    stage: 'authority',
    title: 'Capability grant presented',
    help: 'Authority is separate from identity. A principal must have delegated this agent the right to act.',
  },
  AUTHORITY_SIGNATURE_VALID: {
    stage: 'authority',
    title: 'Grant signature verifies',
    help: 'The principal’s Ed25519 proof over the grant must verify, and the signer must be the declared principal.',
  },
  AUTHORITY_PRINCIPAL_BOUND: {
    stage: 'authority',
    title: 'Grant principal is the attested controller',
    help: 'The credential attests who controls the agent; the grant must come from that same principal. Otherwise anyone could “delegate” authority.',
  },
  AUTHORITY_ACTION_MATCH: {
    stage: 'authority',
    title: 'Action is within the grant',
    help: 'The requested action must be listed in the grant’s authorization details.',
  },
  AUTHORITY_RESOURCE_MATCH: {
    stage: 'authority',
    title: 'Resource is within the grant',
    help: 'The requested resource must match one of the grant’s location patterns (e.g. vendor:*).',
  },
  AUTHORITY_VALIDITY_WINDOW: {
    stage: 'authority',
    title: 'Grant not expired',
    help: 'Delegated authority is time-boxed: now must fall between the grant’s validFrom and validUntil.',
  },
  AUTHORITY_AMOUNT_WITHIN_GRANT: {
    stage: 'authority',
    title: 'Amount within delegated limit',
    help: 'The principal capped what this agent may spend. Valid identity never implies unlimited authority.',
  },
  HISTORY_ATTESTATIONS_VERIFIED: {
    stage: 'history',
    title: 'Counterparty attestations verified',
    help: 'Signed statements from past counterparties are verified cryptographically and counted. They are evidence, not a score, and can never override a failed check above.',
  },
  POLICY_AMOUNT_WITHIN_LIMIT: {
    stage: 'policy',
    title: 'Amount within verifier’s own cap',
    help: 'Independently of the grant, this verifier applies its own spend limit.',
  },
  POLICY_SATISFIED: {
    stage: 'policy',
    title: 'All policy predicates satisfied',
    help: 'ALLOW only when every required predicate passed. The decision is the conjunction of checks, not a weighted score.',
  },
};

export const STAGE_ORDER: Stage[] = [
  'identity',
  'signature',
  'freshness',
  'credential',
  'issuer',
  'revocation',
  'authority',
  'history',
  'policy',
];

export const STAGE_LABEL: Record<Stage, string> = {
  identity: 'Identity',
  signature: 'Signature',
  freshness: 'Freshness',
  credential: 'Credential',
  issuer: 'Issuer',
  revocation: 'Revocation',
  authority: 'Authority',
  history: 'History',
  policy: 'Policy',
};
