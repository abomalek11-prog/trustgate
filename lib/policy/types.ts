import type { Amount, DID, ISODateTime } from '../types';
import type { DecisionReceipt } from '../receipts/types';

/**
 * Declarative, verifier-local policy. A judge can read this JSON and predict
 * the decision. Changing one field changes the outcome — that is the point:
 * trust is evaluated by the verifier's own rules over verifiable evidence.
 */
export interface Policy {
  policyId: string;
  version: number;
  description: string;
  /** The action this policy governs (e.g. "purchase") */
  action: string;
  require: {
    /** request must carry a valid signature from the key inside `from` */
    identityProof: boolean;
    /** request.to must equal this verifier's DID (audience check, RFC 8725 §3.9) */
    audienceMatch: boolean;
    /** reject requests older than this (seconds) */
    requestMaxAgeSeconds: number;
    /** reject a nonce the verifier has already consumed */
    rejectReusedNonce: boolean;
    /** at least one presented credential of each listed type, about `from` */
    credentialTypes: string[];
    /** credential issuers this verifier trusts (DIDs) */
    trustedIssuers: DID[];
    /** credential status must be checked and not revoked */
    notRevoked: boolean;
    authority: {
      /** the requested action must appear in a presented grant */
      action: string;
      /** verifier-local spend cap; null = no verifier cap (the grant still caps) */
      maxAmount: Amount | null;
      /** grant.principal must equal the credential's attested controller */
      principalMustBeCredentialController: boolean;
    };
    /** minimum number of cryptographically verified counterparty attestations */
    minVerifiedAttestations: number;
  };
}

export type CheckStatus = 'pass' | 'fail' | 'skip' | 'warn';

export type Stage =
  | 'identity'
  | 'signature'
  | 'freshness'
  | 'credential'
  | 'issuer'
  | 'revocation'
  | 'authority'
  | 'history'
  | 'policy';

export type CheckId =
  | 'IDENTITY_RESOLVED'
  | 'REQUEST_AUDIENCE_MATCH'
  | 'REQUEST_SIGNATURE_VALID'
  | 'REQUEST_FRESH'
  | 'NONCE_UNSEEN'
  | 'CREDENTIAL_PRESENT'
  | 'CREDENTIAL_SIGNATURE_VALID'
  | 'CREDENTIAL_VALIDITY_WINDOW'
  | 'CREDENTIAL_ISSUER_TRUSTED'
  | 'CREDENTIAL_NOT_REVOKED'
  | 'AUTHORITY_PRESENT'
  | 'AUTHORITY_SIGNATURE_VALID'
  | 'AUTHORITY_PRINCIPAL_BOUND'
  | 'AUTHORITY_ACTION_MATCH'
  | 'AUTHORITY_RESOURCE_MATCH'
  | 'AUTHORITY_VALIDITY_WINDOW'
  | 'AUTHORITY_AMOUNT_WITHIN_GRANT'
  | 'HISTORY_ATTESTATIONS_VERIFIED'
  | 'POLICY_AMOUNT_WITHIN_LIMIT'
  | 'POLICY_SATISFIED';

export interface Check {
  id: CheckId;
  stage: Stage;
  title: string;
  status: CheckStatus;
  /** one-line, human-readable finding */
  detail: string;
  /** whether a `fail` here forces DENY */
  critical: boolean;
  /** pointers to the evidence this check examined (ids, DIDs, hashes) */
  evidence: Record<string, string>;
}

export interface EvidenceRefs {
  presentedBy: DID;
  requestHash: string;
  credentialIds: string[];
  grantIds: string[];
  attestationIds: string[];
  statusListIds: string[];
  issuerDids: DID[];
  principalDids: DID[];
}

export interface Decision {
  allow: boolean;
  decision: 'ALLOW' | 'DENY';
  policyId: string;
  policyHash: string;
  verifier: DID;
  subject: DID;
  action: string;
  resource: string;
  amount?: Amount;
  requestId: string;
  requestHash: string;
  checks: Check[];
  failedChecks: Check[];
  /** plain-English reason a non-crypto judge understands in seconds */
  explanation: string;
  evidence: EvidenceRefs;
  timestamp: ISODateTime;
  durationMs: number;
  /** signed by the verifier; present for every decision */
  receipt?: DecisionReceipt;
}
