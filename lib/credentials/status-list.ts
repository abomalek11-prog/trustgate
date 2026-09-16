/**
 * Revocation via an issuer-signed status list (subset of W3C Bitstring Status List v1.0).
 * https://www.w3.org/TR/vc-bitstring-status-list/
 *
 * Each credential points at { statusListCredential, statusListIndex }. The issuer
 * publishes a signed credential whose subject carries a bitstring; bit N set => the
 * credential with index N is revoked. Revocation therefore is *also* a signed
 * artifact — a verifier only trusts a status list signed by the credential's issuer.
 *
 * Subset notes: the bitstring is not GZIP-compressed and defaults to 1024 entries
 * instead of the 131,072-entry minimum the spec recommends for herd privacy.
 */
import { signDocument, verifyDocument, type ProofVerification } from '../crypto/data-integrity';
import { multibaseB64urlDecode, multibaseB64urlEncode } from '../crypto/encoding';
import {
  didFromVerificationMethod,
  resolvePublicKeyForVerificationMethod,
  verificationMethodId,
} from '../identity/did-key';
import type { ISODateTime, Signer } from '../types';
import { TRUSTGATE_CONTEXT, VC_V2_CONTEXT } from '../types';
import type { StatusListCredential, UnsignedStatusListCredential } from './types';

export const DEFAULT_STATUS_LIST_SIZE = 1024;

export function emptyBitstring(size = DEFAULT_STATUS_LIST_SIZE): Uint8Array {
  return new Uint8Array(Math.ceil(size / 8));
}

export function getBit(bits: Uint8Array, index: number): boolean {
  const byte = bits[Math.floor(index / 8)];
  if (byte === undefined) return false;
  return (byte & (1 << index % 8)) !== 0;
}

export function setBit(bits: Uint8Array, index: number, value: boolean): Uint8Array {
  const out = new Uint8Array(bits);
  const i = Math.floor(index / 8);
  if (i >= out.length) throw new Error('statusListIndex out of range');
  if (value) out[i] |= 1 << index % 8;
  else out[i] &= ~(1 << index % 8);
  return out;
}

export function decodeList(list: StatusListCredential): Uint8Array {
  return multibaseB64urlDecode(list.credentialSubject.encodedList);
}

export interface CreateStatusListParams {
  issuer: Signer;
  id: string;
  size?: number;
  validFrom: ISODateTime;
}

function signList(
  unsigned: UnsignedStatusListCredential,
  issuer: Signer,
  created: ISODateTime,
): StatusListCredential {
  return signDocument(unsigned, issuer.secretKey, {
    verificationMethod: verificationMethodId(issuer.did),
    proofPurpose: 'assertionMethod',
    created,
  });
}

export function createStatusList(p: CreateStatusListParams): StatusListCredential {
  const unsigned: UnsignedStatusListCredential = {
    '@context': [VC_V2_CONTEXT, TRUSTGATE_CONTEXT],
    id: p.id,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: p.issuer.did,
    validFrom: p.validFrom,
    credentialSubject: {
      id: p.id + '#list',
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList: multibaseB64urlEncode(emptyBitstring(p.size)),
    },
  };
  return signList(unsigned, p.issuer, p.validFrom);
}

/** Returns a NEW signed status list with the given index revoked (or restored). */
export function setRevoked(
  list: StatusListCredential,
  issuer: Signer,
  index: number,
  revoked: boolean,
  now: ISODateTime,
): StatusListCredential {
  if (issuer.did !== list.issuer) throw new Error('Only the issuing DID can update its status list');
  const bits = setBit(decodeList(list), index, revoked);
  const { proof: _previous, ...unsigned } = list;
  void _previous;
  const updated: UnsignedStatusListCredential = {
    ...unsigned,
    validFrom: now,
    credentialSubject: { ...unsigned.credentialSubject, encodedList: multibaseB64urlEncode(bits) },
  };
  return signList(updated, issuer, now);
}

export function isRevoked(list: StatusListCredential, index: number): boolean {
  return getBit(decodeList(list), index);
}

export function revokedIndices(list: StatusListCredential): number[] {
  const bits = decodeList(list);
  const out: number[] = [];
  for (let i = 0; i < bits.length * 8; i++) if (getBit(bits, i)) out.push(i);
  return out;
}

export interface StatusListVerification {
  proof: ProofVerification;
  /** proof signer DID equals list.issuer */
  issuerMatchesSigner: boolean;
  /** list.issuer equals the credential's issuer (a status list from anyone else is meaningless) */
  issuerMatchesExpected: boolean;
  valid: boolean;
}

export function verifyStatusList(list: StatusListCredential, expectedIssuer: string): StatusListVerification {
  const proof = verifyDocument(list, resolvePublicKeyForVerificationMethod);
  const signer = proof.verificationMethod ? didFromVerificationMethod(proof.verificationMethod) : '';
  const issuerMatchesSigner = signer === list.issuer;
  const issuerMatchesExpected = list.issuer === expectedIssuer;
  return {
    proof,
    issuerMatchesSigner,
    issuerMatchesExpected,
    valid: proof.valid && issuerMatchesSigner && issuerMatchesExpected,
  };
}
