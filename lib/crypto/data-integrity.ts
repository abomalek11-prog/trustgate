/**
 * W3C Data Integrity proofs with the `eddsa-jcs-2022` cryptosuite.
 * Spec: https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022
 *
 * Algorithm (sign):
 *   1. unsecured  = document without `proof`
 *   2. proofConfig = proof options (+ the document's `@context`, if any)
 *   3. hashData   = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecured))
 *   4. proofValue = multibase-base58btc( Ed25519.sign(hashData) )
 *
 * Verification recomputes hashData from the received document and checks the
 * signature against the public key resolved from `proof.verificationMethod`.
 *
 * Every signed object in TrustGate (credentials, status lists, capability
 * grants, action requests, attestations, decision receipts) uses this one
 * function pair, so there is exactly one signing code path to audit.
 */
import { concatBytes } from '@noble/hashes/utils.js';
import type { DataIntegrityProof, ISODateTime, ProofPurpose, Signed } from '../types';
import { jcs } from './canonicalize';
import { sha256Bytes } from './hash';
import { multibaseB58btcDecode, multibaseB58btcEncode, utf8ToBytes } from './encoding';
import { sign, verify } from './ed25519';

export interface ProofOptions {
  verificationMethod: string;
  proofPurpose: ProofPurpose;
  created: ISODateTime;
}

export type PublicKeyResolver = (verificationMethod: string) => Uint8Array | null;

export type ProofFailureCode =
  | 'MISSING_PROOF'
  | 'UNSUPPORTED_SUITE'
  | 'UNRESOLVABLE_KEY'
  | 'MALFORMED_PROOF_VALUE'
  | 'SIGNATURE_MISMATCH';

export interface ProofVerification {
  valid: boolean;
  /** Machine-friendly reason code */
  code: 'VALID' | ProofFailureCode;
  reason: string;
  verificationMethod?: string;
}

type JsonObject = Record<string, unknown>;

function buildProofConfig(doc: JsonObject, proof: Omit<DataIntegrityProof, 'proofValue'>): JsonObject {
  const config: JsonObject = {
    type: proof.type,
    cryptosuite: proof.cryptosuite,
    created: proof.created,
    verificationMethod: proof.verificationMethod,
    proofPurpose: proof.proofPurpose,
  };
  if ('@context' in doc) config['@context'] = doc['@context'];
  return config;
}

function hashData(doc: JsonObject, proofConfig: JsonObject): Uint8Array {
  const proofHash = sha256Bytes(utf8ToBytes(jcs(proofConfig)));
  const docHash = sha256Bytes(utf8ToBytes(jcs(doc)));
  return concatBytes(proofHash, docHash);
}

export function signDocument<T extends object>(
  document: T,
  secretKey: Uint8Array,
  opts: ProofOptions,
): Signed<T> {
  const { proof: existingProof, ...unsecured } = document as JsonObject & { proof?: unknown };
  void existingProof; // a re-signed document drops any previous proof
  const proofSansValue: Omit<DataIntegrityProof, 'proofValue'> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: opts.created,
    verificationMethod: opts.verificationMethod,
    proofPurpose: opts.proofPurpose,
  };
  const config = buildProofConfig(unsecured, proofSansValue);
  const signature = sign(hashData(unsecured, config), secretKey);
  const proof: DataIntegrityProof = { ...proofSansValue, proofValue: multibaseB58btcEncode(signature) };
  return { ...(unsecured as T), proof };
}

export function verifyDocument(document: unknown, resolvePublicKey: PublicKeyResolver): ProofVerification {
  if (!document || typeof document !== 'object') {
    return { valid: false, code: 'MISSING_PROOF', reason: 'Document is not an object' };
  }
  const { proof, ...unsecured } = document as JsonObject & { proof?: Partial<DataIntegrityProof> };
  if (!proof || typeof proof !== 'object') {
    return { valid: false, code: 'MISSING_PROOF', reason: 'Document carries no proof' };
  }
  if (proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022') {
    return {
      valid: false,
      code: 'UNSUPPORTED_SUITE',
      reason: 'Unsupported proof type/cryptosuite: ' + String(proof.type) + '/' + String(proof.cryptosuite),
    };
  }
  if (!proof.verificationMethod || !proof.proofValue || !proof.created || !proof.proofPurpose) {
    return { valid: false, code: 'MISSING_PROOF', reason: 'Proof is missing required fields' };
  }
  const publicKey = resolvePublicKey(proof.verificationMethod);
  if (!publicKey) {
    return {
      valid: false,
      code: 'UNRESOLVABLE_KEY',
      reason: 'Could not resolve a public key for ' + proof.verificationMethod,
      verificationMethod: proof.verificationMethod,
    };
  }
  let signature: Uint8Array;
  try {
    signature = multibaseB58btcDecode(proof.proofValue);
  } catch {
    return {
      valid: false,
      code: 'MALFORMED_PROOF_VALUE',
      reason: 'proofValue is not valid multibase base58btc',
      verificationMethod: proof.verificationMethod,
    };
  }
  const config = buildProofConfig(unsecured, {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: proof.created,
    verificationMethod: proof.verificationMethod,
    proofPurpose: proof.proofPurpose,
  });
  const ok = verify(signature, hashData(unsecured, config), publicKey);
  if (ok) {
    return {
      valid: true,
      code: 'VALID',
      reason: 'Ed25519 signature verifies against the resolved key',
      verificationMethod: proof.verificationMethod,
    };
  }
  return {
    valid: false,
    code: 'SIGNATURE_MISMATCH',
    reason: 'Ed25519 signature does NOT verify: the document was altered after signing or was signed by a different key',
    verificationMethod: proof.verificationMethod,
  };
}
