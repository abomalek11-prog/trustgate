/**
 * Behavioral evidence: signed statements about what actually happened.
 *
 * - Attestation: a counterparty signs "I observed agent X complete action Y".
 *   It is contextual, signed, and attributable — the opposite of a global score.
 * - Decision Receipt: the verifier signs its own ALLOW/DENY decision, bound to
 *   the request hash and policy hash, so the decision itself is auditable later.
 */
import type { Amount, DID, ISODateTime, Signed } from '../types';

export type AttestationOutcome = 'completed' | 'failed' | 'disputed';

export interface UnsignedAttestation {
  '@context': string[];
  id: string;
  type: ['Attestation'];
  /** who is attesting (signs) */
  issuer: DID;
  /** the agent the statement is about */
  subject: DID;
  action: string;
  resource?: string;
  amount?: Amount;
  outcome: AttestationOutcome;
  /** hash of the ActionRequest this attestation refers to, if any */
  requestHash?: string;
  observedAt: ISODateTime;
  statement: string;
}

export type Attestation = Signed<UnsignedAttestation>;

export interface ReceiptCheck {
  id: string;
  status: 'pass' | 'fail' | 'skip' | 'warn';
}

export interface UnsignedDecisionReceipt {
  '@context': string[];
  id: string;
  type: ['DecisionReceipt'];
  verifier: DID;
  subject: DID;
  requestId: string;
  requestHash: string;
  action: string;
  resource: string;
  amount?: Amount;
  decision: 'ALLOW' | 'DENY';
  policyId: string;
  policyHash: string;
  checks: ReceiptCheck[];
  issuedAt: ISODateTime;
}

export type DecisionReceipt = Signed<UnsignedDecisionReceipt>;
