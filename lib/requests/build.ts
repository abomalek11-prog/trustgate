import { signDocument } from '../crypto/data-integrity';
import { b64url } from '../crypto/encoding';
import { randomNonce } from '../crypto/ed25519';
import { verificationMethodId } from '../identity/did-key';
import type { DID } from '../types';
import { TRUSTGATE_CONTEXT } from '../types';
import type { ActionParams, ActionRequest, Presentation, UnsignedActionRequest } from './types';

export const DEFAULT_REQUEST_TTL_SECONDS = 60;

export function newNonce(): string {
  return b64url.encode(randomNonce(16));
}

export function newRequestId(): string {
  const id = typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : b64url.encode(randomNonce(16));
  return 'urn:uuid:' + id;
}

export interface BuildRequestParams {
  /** The DID the request CLAIMS to come from. */
  from: DID;
  /**
   * The key that actually signs. Normally the key behind `from`; a spoofing
   * attacker supplies a different key here and the signature check fails.
   */
  signingKey: Uint8Array;
  /** verificationMethod to declare in the proof; defaults to `from`'s own key id */
  verificationMethod?: string;
  to: DID;
  action: string;
  resource: string;
  params: ActionParams;
  presentation: Presentation;
  now: Date;
  ttlSeconds?: number;
  nonce?: string;
  id?: string;
}

export function buildActionRequest(p: BuildRequestParams): ActionRequest {
  const ttl = p.ttlSeconds ?? DEFAULT_REQUEST_TTL_SECONDS;
  const issuedAt = p.now.toISOString();
  const expiresAt = new Date(p.now.getTime() + ttl * 1000).toISOString();
  const unsigned: UnsignedActionRequest = {
    '@context': [TRUSTGATE_CONTEXT],
    type: ['ActionRequest'],
    id: p.id ?? newRequestId(),
    from: p.from,
    to: p.to,
    action: p.action,
    resource: p.resource,
    params: p.params,
    nonce: p.nonce ?? newNonce(),
    issuedAt,
    expiresAt,
    presentation: p.presentation,
  };
  return signDocument(unsigned, p.signingKey, {
    verificationMethod: p.verificationMethod ?? verificationMethodId(p.from),
    proofPurpose: 'authentication',
    created: issuedAt,
  });
}
