/**
 * TrustGate engine — Identity -> Claims -> Verification -> Policy -> Decision Receipt
 *
 *   crypto/       Ed25519, JCS canonicalization, SHA-256, Data Integrity proofs
 *   identity/     did:key identifiers and resolution
 *   credentials/  W3C VC 2.0 issuance, verification, signed status lists (revocation)
 *   authority/    signed, scoped capability grants (RFC 9396-style authorization details)
 *   requests/     the signed ActionRequest envelope that crosses between agents
 *   receipts/     counterparty attestations + signed decision receipts
 *   policy/       declarative policy + the predicate engine that produces a Decision
 *   verifier/     the receiving agent's gate: state (nonces, status lists) + receipt signing
 *   demo/         deterministic synthetic actors and attack scenarios
 */
export * from './types';
export * from './crypto';
export * from './identity';
export * from './credentials';
export * from './authority';
export * from './requests';
export * from './receipts';
export * from './policy';
export * from './verifier';
export * from './demo';
