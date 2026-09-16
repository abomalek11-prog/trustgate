/**
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │  SYNTHETIC DEMO IDENTITIES — NOT SECRETS                             │
 * │                                                                      │
 * │  Every demo keypair is derived from SHA-256("trustgate-demo-v1:" +   │
 * │  label). That makes the fixtures deterministic (same DIDs on every   │
 * │  machine, every load, every test run) and makes it impossible to     │
 * │  mistake them for real credentials: anyone can re-derive them.       │
 * │  Production deployments must generate keys with a CSPRNG/HSM.        │
 * └──────────────────────────────────────────────────────────────────────┘
 */
import { sha256Bytes, sha256Hex } from '../crypto/hash';
import { keyPairFromSeed } from '../crypto/ed25519';
import { didKeyFromPublicKey } from '../identity/did-key';
import type { DID, KeyPair } from '../types';

export const DEMO_SEED_NAMESPACE = 'trustgate-demo-v1:';

/** The fixed "creation date" of the fixture set, so signed fixtures are byte-identical across runs. */
export const FIXTURE_EPOCH = '2026-09-01T00:00:00Z';

export function demoSeed(label: string): Uint8Array {
  return sha256Bytes(DEMO_SEED_NAMESPACE + label);
}

export function demoKeys(label: string): KeyPair {
  return keyPairFromSeed(demoSeed(label));
}

export function demoIdentity(label: string): { did: DID; keys: KeyPair } {
  const keys = demoKeys(label);
  return { did: didKeyFromPublicKey(keys.publicKey), keys };
}

/** Deterministic, UUID-shaped id derived from a label (for fixture credential/grant ids). */
export function demoUuid(label: string): string {
  const h = sha256Hex(DEMO_SEED_NAMESPACE + 'uuid:' + label);
  return 'urn:uuid:' + h.slice(0, 8) + '-' + h.slice(8, 12) + '-5' + h.slice(13, 16) + '-a' + h.slice(17, 20) + '-' + h.slice(20, 32);
}
