/**
 * Granular credential checks. Each function answers ONE question so the policy
 * engine can surface every predicate separately in the verification trace.
 */
import { verifyDocument, type ProofVerification } from '../crypto/data-integrity';
import { didFromVerificationMethod, resolvePublicKeyForVerificationMethod } from '../identity/did-key';
import type { DID } from '../types';
import { isRevoked, verifyStatusList, type StatusListVerification } from './status-list';
import type { StatusListCredential, VerifiableCredential } from './types';

export interface CredentialProofResult {
  proof: ProofVerification;
  /** The DID that actually signed (from proof.verificationMethod) */
  signer: DID | null;
  /** `issuer` field equals the signing DID — prevents "signed by X, claims issuer Y" */
  issuerMatchesSigner: boolean;
  valid: boolean;
}

export function verifyCredentialProof(vc: VerifiableCredential): CredentialProofResult {
  const proof = verifyDocument(vc, resolvePublicKeyForVerificationMethod);
  const signer = proof.verificationMethod ? didFromVerificationMethod(proof.verificationMethod) : null;
  const issuerMatchesSigner = signer !== null && signer === vc.issuer;
  return { proof, signer, issuerMatchesSigner, valid: proof.valid && issuerMatchesSigner };
}

export interface ValidityResult {
  active: boolean;
  notYetValid: boolean;
  expired: boolean;
  validFrom: string;
  validUntil?: string;
}

export function checkValidityWindow(
  doc: { validFrom: string; validUntil?: string },
  now: Date,
): ValidityResult {
  const from = Date.parse(doc.validFrom);
  const until = doc.validUntil ? Date.parse(doc.validUntil) : Number.POSITIVE_INFINITY;
  const t = now.getTime();
  const notYetValid = Number.isNaN(from) || t < from;
  const expired = Number.isNaN(until) || t >= until;
  return {
    active: !notYetValid && !expired,
    notYetValid,
    expired,
    validFrom: doc.validFrom,
    validUntil: doc.validUntil,
  };
}

export interface StatusCheckResult {
  /** credential carries a credentialStatus entry */
  hasStatus: boolean;
  /** a status list was available to the verifier */
  listAvailable: boolean;
  listVerification?: StatusListVerification;
  revoked: boolean;
  index?: number;
  listUpdatedAt?: string;
  /** true only when: status present, list available, list authentic, bit not set */
  ok: boolean;
  reason: string;
}

export type StatusListResolver = (statusListCredentialId: string) => StatusListCredential | undefined;

export function checkCredentialStatus(
  vc: VerifiableCredential,
  resolveStatusList: StatusListResolver,
): StatusCheckResult {
  const status = vc.credentialStatus;
  if (!status) {
    return {
      hasStatus: false,
      listAvailable: false,
      revoked: false,
      ok: false,
      reason: 'Credential has no credentialStatus; revocation cannot be checked (fail closed)',
    };
  }
  const index = Number(status.statusListIndex);
  const list = resolveStatusList(status.statusListCredential);
  if (!list) {
    return {
      hasStatus: true,
      listAvailable: false,
      revoked: false,
      index,
      ok: false,
      reason: 'Status list ' + status.statusListCredential + ' is not available (fail closed)',
    };
  }
  const listVerification = verifyStatusList(list, vc.issuer);
  if (!listVerification.valid) {
    return {
      hasStatus: true,
      listAvailable: true,
      listVerification,
      revoked: false,
      index,
      listUpdatedAt: list.validFrom,
      ok: false,
      reason: 'Status list is not authentically signed by the credential issuer (fail closed)',
    };
  }
  const revoked = isRevoked(list, index);
  return {
    hasStatus: true,
    listAvailable: true,
    listVerification,
    revoked,
    index,
    listUpdatedAt: list.validFrom,
    ok: !revoked,
    reason: revoked
      ? 'Issuer-signed status list marks index ' + index + ' as REVOKED'
      : 'Issuer-signed status list (published ' + list.validFrom + ') shows index ' + index + ' not revoked',
  };
}

export function credentialHasType(vc: VerifiableCredential, type: string): boolean {
  return Array.isArray(vc.type) && vc.type.includes(type);
}
