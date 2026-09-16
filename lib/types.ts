/**
 * Shared primitive types used across every TrustGate layer.
 *
 *   Identity -> Claims -> Verification -> Policy -> Decision Receipt
 */

/** A Decentralized Identifier, e.g. `did:key:z6Mk...` */
export type DID = string;

/** RFC 3339 / ISO 8601 timestamp in UTC, e.g. `2026-09-01T00:00:00Z` */
export type ISODateTime = string;

export interface Amount {
  value: number;
  currency: 'USD';
}

export interface KeyPair {
  /** 32-byte Ed25519 public key */
  publicKey: Uint8Array;
  /** 32-byte Ed25519 secret-key seed (RFC 8032) */
  secretKey: Uint8Array;
}

/** Something that can sign: a DID plus the secret key that controls it. */
export interface Signer {
  did: DID;
  secretKey: Uint8Array;
}

export type ProofPurpose =
  | 'assertionMethod'
  | 'authentication'
  | 'capabilityDelegation'
  | 'capabilityInvocation';

/**
 * W3C Data Integrity proof using the `eddsa-jcs-2022` cryptosuite:
 * JCS canonicalization (RFC 8785) + SHA-256 + Ed25519.
 * https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022
 */
export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  created: ISODateTime;
  /** e.g. `did:key:z6Mk...#z6Mk...` */
  verificationMethod: string;
  proofPurpose: ProofPurpose;
  /** multibase base58btc (`z` prefix) of the 64-byte Ed25519 signature */
  proofValue: string;
}

export type Signed<T> = T & { proof: DataIntegrityProof };

export const TRUSTGATE_CONTEXT = 'https://trustgate.dev/ns/v1';
export const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
