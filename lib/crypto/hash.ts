import { sha256 } from '@noble/hashes/sha2.js';
import { toHex, utf8ToBytes } from './encoding';
import { jcs } from './canonicalize';

export function sha256Bytes(data: Uint8Array | string): Uint8Array {
  return sha256(typeof data === 'string' ? utf8ToBytes(data) : data);
}

export function sha256Hex(data: Uint8Array | string): string {
  return toHex(sha256Bytes(data));
}

/**
 * Content hash of a JSON document: `sha256:<hex>` over its JCS canonical form.
 * Used for request hashes, policy hashes and receipt binding.
 */
export function hashDocument(doc: unknown): string {
  return 'sha256:' + sha256Hex(jcs(doc));
}

/** Short, human-friendly key fingerprint for UI display (first 16 hex chars of SHA-256). */
export function fingerprint(bytes: Uint8Array): string {
  return sha256Hex(bytes).slice(0, 16);
}
