import { describe, expect, it } from 'vitest';
import { jcs } from '@/lib/crypto/canonicalize';
import { generateKeyPair, keyPairFromSeed, sign, verify } from '@/lib/crypto/ed25519';
import { signDocument, verifyDocument } from '@/lib/crypto/data-integrity';
import { hashDocument, sha256Hex } from '@/lib/crypto/hash';
import { utf8ToBytes } from '@/lib/crypto/encoding';
import {
  didKeyFromPublicKey,
  resolveDidKey,
  resolvePublicKeyForVerificationMethod,
  verificationMethodId,
} from '@/lib/identity/did-key';
import { demoSeed } from '@/lib/demo/seeds';

describe('JCS canonicalization (RFC 8785)', () => {
  it('matches the RFC 8785 §3.2.3 test vector', () => {
    // Build the RFC's string from code points so no escape sequence is ambiguous:
    // U+20AC $ U+000F U+000A A ' B " \ \ " /
    const euro = String.fromCodePoint(0x20ac);
    const si = String.fromCodePoint(0x0f);
    const lf = String.fromCodePoint(0x0a);
    const bs = String.fromCodePoint(0x5c);
    const q = String.fromCodePoint(0x22);
    const input = {
      numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001],
      string: euro + '$' + si + lf + "A'B" + q + bs + bs + q + '/',
      literals: [null, true, false],
    };
    const expected =
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"' +
      euro + '$' + bs + 'u000f' + bs + 'nA' + "'" + 'B' + bs + q + bs + bs + bs + bs + bs + q + '/"}';
    expect(jcs(input)).toBe(expected);
  });

  it('is key-order independent', () => {
    expect(jcs({ b: 1, a: { d: 2, c: 3 } })).toBe(jcs({ a: { c: 3, d: 2 }, b: 1 }));
  });

  it('rejects unserializable values', () => {
    expect(() => jcs(undefined)).toThrow();
    expect(() => jcs(Number.NaN)).toThrow();
  });
});

describe('Ed25519 via @noble/ed25519', () => {
  it('signs and verifies; rejects a flipped bit', () => {
    const kp = generateKeyPair();
    const msg = utf8ToBytes('hello agents');
    const sig = sign(msg, kp.secretKey);
    expect(sig.length).toBe(64);
    expect(verify(sig, msg, kp.publicKey)).toBe(true);
    const bad = new Uint8Array(sig);
    bad[10] ^= 1;
    expect(verify(bad, msg, kp.publicKey)).toBe(false);
    expect(verify(sig, utf8ToBytes('hello agentz'), kp.publicKey)).toBe(false);
    expect(verify(sig, msg, generateKeyPair().publicKey)).toBe(false);
  });

  it('derives deterministic demo keys from labelled seeds', () => {
    const a = keyPairFromSeed(demoSeed('agent:buyer'));
    const b = keyPairFromSeed(demoSeed('agent:buyer'));
    expect(Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey))).toBe(true);
    expect(Buffer.from(a.publicKey).equals(Buffer.from(keyPairFromSeed(demoSeed('agent:clone')).publicKey))).toBe(false);
  });
});

describe('did:key', () => {
  it('round-trips an Ed25519 public key', () => {
    const kp = generateKeyPair();
    const did = didKeyFromPublicKey(kp.publicKey);
    expect(did.startsWith('did:key:z6Mk')).toBe(true);
    const r = resolveDidKey(did);
    expect(r).not.toBeNull();
    expect(Buffer.from(r!.publicKey).equals(Buffer.from(kp.publicKey))).toBe(true);
    expect(r!.document.verificationMethod[0].id).toBe(verificationMethodId(did));
    expect(r!.document.verificationMethod[0].type).toBe('Multikey');
  });

  it('rejects malformed identifiers and foreign fragments', () => {
    expect(resolveDidKey('did:key:zNotAKey')).toBeNull();
    expect(resolveDidKey('did:web:example.com')).toBeNull();
    expect(resolveDidKey(42)).toBeNull();
    const a = didKeyFromPublicKey(generateKeyPair().publicKey);
    const b = didKeyFromPublicKey(generateKeyPair().publicKey);
    // did:key:A#<B's key> must NOT resolve — the fragment must be A's own key
    expect(resolvePublicKeyForVerificationMethod(a + '#' + b.slice('did:key:'.length))).toBeNull();
    expect(resolvePublicKeyForVerificationMethod(verificationMethodId(a))).not.toBeNull();
  });
});

describe('Data Integrity eddsa-jcs-2022', () => {
  const kp = generateKeyPair();
  const did = didKeyFromPublicKey(kp.publicKey);
  const doc = { '@context': ['https://trustgate.dev/ns/v1'], id: 'urn:x', claims: { level: 2 } };
  const signed = signDocument(doc, kp.secretKey, {
    verificationMethod: verificationMethodId(did),
    proofPurpose: 'assertionMethod',
    created: '2026-09-01T00:00:00Z',
  });

  it('produces a verifiable proof', () => {
    expect(signed.proof.type).toBe('DataIntegrityProof');
    expect(signed.proof.cryptosuite).toBe('eddsa-jcs-2022');
    expect(signed.proof.proofValue.startsWith('z')).toBe(true);
    expect(verifyDocument(signed, resolvePublicKeyForVerificationMethod).valid).toBe(true);
  });

  it('is deterministic for identical input', () => {
    const again = signDocument(doc, kp.secretKey, {
      verificationMethod: verificationMethodId(did),
      proofPurpose: 'assertionMethod',
      created: '2026-09-01T00:00:00Z',
    });
    expect(again.proof.proofValue).toBe(signed.proof.proofValue);
  });

  it('fails on any field change, including reordering-insensitive edits', () => {
    const tampered = { ...signed, claims: { level: 3 } };
    const r = verifyDocument(tampered, resolvePublicKeyForVerificationMethod);
    expect(r.valid).toBe(false);
    expect(r.code).toBe('SIGNATURE_MISMATCH');
    // reordering keys does NOT break the proof (canonicalization)
    const reordered = { claims: { level: 2 }, id: 'urn:x', '@context': ['https://trustgate.dev/ns/v1'], proof: signed.proof };
    expect(verifyDocument(reordered, resolvePublicKeyForVerificationMethod).valid).toBe(true);
  });

  it('fails when the proof names a key that did not sign', () => {
    const other = generateKeyPair();
    const otherDid = didKeyFromPublicKey(other.publicKey);
    const forged = { ...signed, proof: { ...signed.proof, verificationMethod: verificationMethodId(otherDid) } };
    expect(verifyDocument(forged, resolvePublicKeyForVerificationMethod).code).toBe('SIGNATURE_MISMATCH');
  });

  it('reports missing / unsupported proofs', () => {
    expect(verifyDocument(doc, resolvePublicKeyForVerificationMethod).code).toBe('MISSING_PROOF');
    expect(verifyDocument({ ...signed, proof: { ...signed.proof, cryptosuite: 'rsa' } }, resolvePublicKeyForVerificationMethod).code).toBe('UNSUPPORTED_SUITE');
  });
});

describe('hashing', () => {
  it('hashDocument is canonical', () => {
    expect(hashDocument({ a: 1, b: 2 })).toBe(hashDocument({ b: 2, a: 1 }));
    expect(hashDocument({ a: 1 })).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});
