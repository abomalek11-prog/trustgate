/**
 * The signed message that crosses between agents.
 *
 * An ActionRequest is what Agent A sends to Agent B: "I (from) ask you (to) to
 * perform ACTION on RESOURCE with PARAMS, here is my evidence". The whole
 * envelope — including the presented evidence — is signed by `from`, so:
 *   - a clone that copies A's DID cannot produce a valid proof (spoofing),
 *   - a replayed envelope carries a nonce/timestamp the verifier already saw,
 *   - evidence inside is itself issuer-signed, so tampering with it breaks the
 *     issuer's proof even if the presenter re-signs the envelope.
 */
import type { Amount, DID, ISODateTime, Signed } from '../types';
import type { VerifiableCredential } from '../credentials/types';
import type { CapabilityGrant } from '../authority/types';
import type { Attestation } from '../receipts/types';

/** Evidence the requester chooses to present (akin to a Verifiable Presentation). */
export interface Presentation {
  credentials: VerifiableCredential[];
  grants: CapabilityGrant[];
  attestations: Attestation[];
}

export interface ActionParams {
  amount?: Amount;
  description?: string;
  [k: string]: unknown;
}

export interface UnsignedActionRequest {
  '@context': string[];
  type: ['ActionRequest'];
  id: string;
  from: DID;
  to: DID;
  action: string;
  resource: string;
  params: ActionParams;
  /** 128-bit random, base64url — replay defense together with issuedAt/expiresAt */
  nonce: string;
  issuedAt: ISODateTime;
  expiresAt: ISODateTime;
  presentation: Presentation;
}

export type ActionRequest = Signed<UnsignedActionRequest>;
