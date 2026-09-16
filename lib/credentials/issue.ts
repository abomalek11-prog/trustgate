import { signDocument } from '../crypto/data-integrity';
import { verificationMethodId } from '../identity/did-key';
import type { ISODateTime, Signer } from '../types';
import { TRUSTGATE_CONTEXT, VC_V2_CONTEXT } from '../types';
import type { CredentialSubject, UnsignedCredential, VerifiableCredential } from './types';

export interface IssueCredentialParams {
  issuer: Signer;
  /** Credential id (urn:uuid:...). Deterministic ids are fine for demo fixtures. */
  id: string;
  /** Additional types beyond `VerifiableCredential`, e.g. ['VerifiedBusinessAgent'] */
  types: string[];
  subject: CredentialSubject;
  validFrom: ISODateTime;
  validUntil?: ISODateTime;
  status?: { statusListCredential: string; index: number };
}

/**
 * Issue a VC 2.0 credential signed by the issuer's did:key.
 * The proof is created over the JCS-canonical document, so ANY later edit to
 * ANY field (subject, dates, status pointer, types) invalidates the signature.
 */
export function issueCredential(p: IssueCredentialParams): VerifiableCredential {
  const unsigned: UnsignedCredential = {
    '@context': [VC_V2_CONTEXT, TRUSTGATE_CONTEXT],
    id: p.id,
    type: ['VerifiableCredential', ...p.types],
    issuer: p.issuer.did,
    validFrom: p.validFrom,
    ...(p.validUntil ? { validUntil: p.validUntil } : {}),
    credentialSubject: p.subject,
    ...(p.status
      ? {
          credentialStatus: {
            id: p.status.statusListCredential + '#' + p.status.index,
            type: 'BitstringStatusListEntry' as const,
            statusPurpose: 'revocation' as const,
            statusListIndex: String(p.status.index),
            statusListCredential: p.status.statusListCredential,
          },
        }
      : {}),
  };
  return signDocument(unsigned, p.issuer.secretKey, {
    verificationMethod: verificationMethodId(p.issuer.did),
    proofPurpose: 'assertionMethod',
    created: p.validFrom,
  });
}
