/**
 * Ed25519 signing/verification via the audited, maintained `@noble/ed25519`.
 * We never implement primitives ourselves; this module only adapts the API.
 */
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import type { KeyPair } from '../types';

// Wire a synchronous SHA-512 so the sync API works in Node, Edge and browsers alike.
ed.hashes.sha512 = sha512;

/** Deterministic keypair from a 32-byte seed. Used ONLY for clearly-labelled demo identities. */
export function keyPairFromSeed(seed: Uint8Array): KeyPair {
  if (seed.length !== 32) throw new Error('Ed25519 seed must be 32 bytes');
  const { secretKey, publicKey } = ed.keygen(seed);
  return { secretKey, publicKey };
}

/** Fresh random keypair (CSPRNG). */
export function generateKeyPair(): KeyPair {
  return keyPairFromSeed(randomBytes(32));
}

export function publicKeyFromSecret(secretKey: Uint8Array): Uint8Array {
  return ed.getPublicKey(secretKey);
}

export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ed.sign(message, secretKey);
}

/** Returns false (never throws) on malformed input so callers can treat it as a failed check. */
export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    if (signature.length !== 64 || publicKey.length !== 32) return false;
    // zip215:false = strict RFC 8032 verification (rejects non-canonical encodings).
    return ed.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

export function randomNonce(bytes = 16): Uint8Array {
  return randomBytes(bytes);
}
