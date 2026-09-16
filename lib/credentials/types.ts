/**
 * W3C Verifiable Credentials Data Model 2.0 — interoperable subset.
 * https://www.w3.org/TR/vc-data-model-2.0/
 *
 * We keep the VC 2.0 shape (`@context`, `type`, `issuer`, `validFrom`,
 * `validUntil`, `credentialSubject`, `credentialStatus`, `proof`) and secure it
 * with a Data Integrity `eddsa-jcs-2022` proof. JSON-LD expansion is not
 * performed; documents are canonicalized with JCS (RFC 8785).
 */
import type { DID, ISODateTime, Signed } from '../types';

export interface CredentialSubject {
  id: DID;
  [claim: string]: unknown;
}

/** Modelled on W3C Bitstring Status List entries. */
export interface CredentialStatus {
  id: string;
  type: 'BitstringStatusListEntry';
  statusPurpose: 'revocation';
  statusListIndex: string;
  /** id/URL of the StatusListCredential that carries the bitstring */
  statusListCredential: string;
}

export interface UnsignedCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: DID;
  validFrom: ISODateTime;
  validUntil?: ISODateTime;
  credentialSubject: CredentialSubject;
  credentialStatus?: CredentialStatus;
}

export type VerifiableCredential = Signed<UnsignedCredential>;

export interface StatusListSubject {
  id: string;
  type: 'BitstringStatusList';
  statusPurpose: 'revocation';
  /** multibase base64url (`u` prefix) of the raw bitstring (uncompressed subset) */
  encodedList: string;
}

export interface UnsignedStatusListCredential {
  '@context': string[];
  id: string;
  type: ['VerifiableCredential', 'BitstringStatusListCredential'];
  issuer: DID;
  validFrom: ISODateTime;
  credentialSubject: StatusListSubject;
}

export type StatusListCredential = Signed<UnsignedStatusListCredential>;

/** Well-known credential types used by the demo policy. */
export const VERIFIED_BUSINESS_AGENT = 'VerifiedBusinessAgent';
