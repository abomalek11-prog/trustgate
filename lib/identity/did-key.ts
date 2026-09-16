/**
 * did:key for Ed25519 (W3C DID Core + did:key method spec).
 *
 *   did:key:z6Mk...  =  "did:key:" + multibase-base58btc( 0xed01 || 32-byte public key )
 *
 * The identifier *is* the public key, so identity proof reduces to: can the
 * presenter produce a signature that verifies under the key inside the DID?
 * No registry, no lookup, no platform account.
 */
import { concatBytes } from '@noble/hashes/utils.js';
import type { DID } from '../types';
import { multibaseB58btcDecode, multibaseB58btcEncode } from '../crypto/encoding';

/** multicodec varint for ed25519-pub (0xed) */
const ED25519_PUB_MULTICODEC = new Uint8Array([0xed, 0x01]);
const DID_KEY_PREFIX = 'did:key:';

export interface VerificationMethod {
  id: string;
  type: 'Multikey';
  controller: DID;
  publicKeyMultibase: string;
}

export interface DidDocument {
  '@context': string[];
  id: DID;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  capabilityDelegation: string[];
  capabilityInvocation: string[];
}

export function publicKeyMultibase(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  return multibaseB58btcEncode(concatBytes(ED25519_PUB_MULTICODEC, publicKey));
}

export function didKeyFromPublicKey(publicKey: Uint8Array): DID {
  return DID_KEY_PREFIX + publicKeyMultibase(publicKey);
}

export function isDidKey(did: unknown): did is DID {
  return typeof did === 'string' && did.startsWith(DID_KEY_PREFIX + 'z6Mk');
}

/** The single verification method id of a did:key: `did:key:z6Mk...#z6Mk...` */
export function verificationMethodId(did: DID): string {
  return did + '#' + did.slice(DID_KEY_PREFIX.length);
}

export function didFromVerificationMethod(vm: string): DID {
  return vm.split('#')[0];
}

export interface ResolvedDid {
  did: DID;
  publicKey: Uint8Array;
  document: DidDocument;
}

/** Resolve a did:key into its DID Document + raw public key. Returns null for anything malformed. */
export function resolveDidKey(did: unknown): ResolvedDid | null {
  if (!isDidKey(did)) return null;
  let decoded: Uint8Array;
  try {
    decoded = multibaseB58btcDecode(did.slice(DID_KEY_PREFIX.length));
  } catch {
    return null;
  }
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) return null;
  const publicKey = decoded.slice(2);
  const vmId = verificationMethodId(did);
  const document: DidDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod: [
      { id: vmId, type: 'Multikey', controller: did, publicKeyMultibase: did.slice(DID_KEY_PREFIX.length) },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
    capabilityDelegation: [vmId],
    capabilityInvocation: [vmId],
  };
  return { did, publicKey, document };
}

/**
 * Resolver used by Data Integrity verification: turns a verificationMethod id
 * into a public key. Enforces that the fragment matches the DID's own key, so
 * `did:key:A#B` (a key that does not belong to A) never resolves.
 */
export function resolvePublicKeyForVerificationMethod(vm: string): Uint8Array | null {
  const did = didFromVerificationMethod(vm);
  const resolved = resolveDidKey(did);
  if (!resolved) return null;
  if (vm !== verificationMethodId(did)) return null;
  return resolved.publicKey;
}

/** Short display form: did:key:z6Mk…abcd */
export function shortDid(did: string, tail = 6): string {
  if (!did.startsWith(DID_KEY_PREFIX)) return did;
  const body = did.slice(DID_KEY_PREFIX.length);
  return DID_KEY_PREFIX + body.slice(0, 4) + '…' + body.slice(-tail);
}
