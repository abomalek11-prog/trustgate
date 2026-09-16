import { signDocument, verifyDocument, type ProofVerification } from '../crypto/data-integrity';
import {
  didFromVerificationMethod,
  resolvePublicKeyForVerificationMethod,
  verificationMethodId,
} from '../identity/did-key';
import type { DID, ISODateTime, Signer } from '../types';
import { TRUSTGATE_CONTEXT } from '../types';
import type {
  Attestation,
  DecisionReceipt,
  UnsignedAttestation,
  UnsignedDecisionReceipt,
} from './types';

export interface IssueAttestationParams extends Omit<UnsignedAttestation, '@context' | 'type' | 'issuer'> {
  attester: Signer;
}

export function issueAttestation(p: IssueAttestationParams): Attestation {
  const { attester, ...rest } = p;
  const unsigned: UnsignedAttestation = {
    '@context': [TRUSTGATE_CONTEXT],
    type: ['Attestation'],
    issuer: attester.did,
    ...rest,
  };
  return signDocument(unsigned, attester.secretKey, {
    verificationMethod: verificationMethodId(attester.did),
    proofPurpose: 'assertionMethod',
    created: p.observedAt,
  });
}

export interface SignedDocResult {
  proof: ProofVerification;
  signer: DID | null;
  /** the document's declared author equals the DID that actually signed */
  authorMatchesSigner: boolean;
  valid: boolean;
}

export function verifyAttestation(att: Attestation): SignedDocResult {
  const proof = verifyDocument(att, resolvePublicKeyForVerificationMethod);
  const signer = proof.verificationMethod ? didFromVerificationMethod(proof.verificationMethod) : null;
  const authorMatchesSigner = signer !== null && signer === att.issuer;
  return { proof, signer, authorMatchesSigner, valid: proof.valid && authorMatchesSigner };
}

export interface IssueReceiptParams extends Omit<UnsignedDecisionReceipt, '@context' | 'type' | 'verifier'> {
  verifier: Signer;
  issuedAt: ISODateTime;
}

/** The verifier signs its decision so anyone can later prove what was decided, about which request, under which policy. */
export function issueDecisionReceipt(p: IssueReceiptParams): DecisionReceipt {
  const { verifier, ...rest } = p;
  const unsigned: UnsignedDecisionReceipt = {
    '@context': [TRUSTGATE_CONTEXT],
    type: ['DecisionReceipt'],
    verifier: verifier.did,
    ...rest,
  };
  return signDocument(unsigned, verifier.secretKey, {
    verificationMethod: verificationMethodId(verifier.did),
    proofPurpose: 'assertionMethod',
    created: p.issuedAt,
  });
}

export function verifyDecisionReceipt(receipt: DecisionReceipt): SignedDocResult {
  const proof = verifyDocument(receipt, resolvePublicKeyForVerificationMethod);
  const signer = proof.verificationMethod ? didFromVerificationMethod(proof.verificationMethod) : null;
  const authorMatchesSigner = signer !== null && signer === receipt.verifier;
  return { proof, signer, authorMatchesSigner, valid: proof.valid && authorMatchesSigner };
}
