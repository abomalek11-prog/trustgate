/**
 * Byte <-> text encodings. Nothing here is cryptographic; it only shapes bytes
 * into the multibase / base64url / hex forms the standards expect.
 */
import { base58, base64urlnopad } from '@scure/base';
import { bytesToHex, hexToBytes, utf8ToBytes as nobleUtf8ToBytes } from '@noble/hashes/utils.js';

export const toHex = (bytes: Uint8Array): string => bytesToHex(bytes);
export const fromHex = (hex: string): Uint8Array => hexToBytes(hex);
export const utf8ToBytes = (s: string): Uint8Array => nobleUtf8ToBytes(s);
export const bytesToUtf8 = (b: Uint8Array): string => new TextDecoder().decode(b);

/** Multibase base58btc: `z` + base58btc(bytes). Used by did:key and proofValue. */
export function multibaseB58btcEncode(bytes: Uint8Array): string {
  return 'z' + base58.encode(bytes);
}

export function multibaseB58btcDecode(s: string): Uint8Array {
  if (!s.startsWith('z')) throw new Error('Expected multibase base58btc string starting with "z"');
  return base58.decode(s.slice(1));
}

/** Multibase base64url (no padding): `u` + base64url(bytes). Used by status lists. */
export function multibaseB64urlEncode(bytes: Uint8Array): string {
  return 'u' + base64urlnopad.encode(bytes);
}

export function multibaseB64urlDecode(s: string): Uint8Array {
  if (!s.startsWith('u')) throw new Error('Expected multibase base64url string starting with "u"');
  return base64urlnopad.decode(s.slice(1));
}

export const b64url = {
  encode: (bytes: Uint8Array): string => base64urlnopad.encode(bytes),
  decode: (s: string): Uint8Array => base64urlnopad.decode(s),
};
