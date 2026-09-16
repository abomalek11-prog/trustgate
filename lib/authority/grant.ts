import { signDocument, verifyDocument, type ProofVerification } from '../crypto/data-integrity';
import {
  didFromVerificationMethod,
  resolvePublicKeyForVerificationMethod,
  verificationMethodId,
} from '../identity/did-key';
import type { Amount, DID, ISODateTime, Signer } from '../types';
import { TRUSTGATE_CONTEXT } from '../types';
import type { AuthorizationDetail, CapabilityGrant, UnsignedCapabilityGrant } from './types';

export interface IssueGrantParams {
  principal: Signer;
  agent: DID;
  id: string;
  authorizationDetails: AuthorizationDetail[];
  validFrom: ISODateTime;
  validUntil: ISODateTime;
  nonce: string;
}

/** The principal signs the grant with proofPurpose `capabilityDelegation`. */
export function issueGrant(p: IssueGrantParams): CapabilityGrant {
  const unsigned: UnsignedCapabilityGrant = {
    '@context': [TRUSTGATE_CONTEXT],
    id: p.id,
    type: ['CapabilityGrant'],
    principal: p.principal.did,
    agent: p.agent,
    authorizationDetails: p.authorizationDetails,
    validFrom: p.validFrom,
    validUntil: p.validUntil,
    nonce: p.nonce,
  };
  return signDocument(unsigned, p.principal.secretKey, {
    verificationMethod: verificationMethodId(p.principal.did),
    proofPurpose: 'capabilityDelegation',
    created: p.validFrom,
  });
}

export interface GrantProofResult {
  proof: ProofVerification;
  signer: DID | null;
  /** `principal` equals the DID that signed */
  principalMatchesSigner: boolean;
  valid: boolean;
}

export function verifyGrantProof(grant: CapabilityGrant): GrantProofResult {
  const proof = verifyDocument(grant, resolvePublicKeyForVerificationMethod);
  const signer = proof.verificationMethod ? didFromVerificationMethod(proof.verificationMethod) : null;
  const principalMatchesSigner = signer !== null && signer === grant.principal;
  return { proof, signer, principalMatchesSigner, valid: proof.valid && principalMatchesSigner };
}

/** Glob match where a trailing `*` matches any suffix: `vendor:*` matches `vendor:northwind/credits`. */
export function resourceMatches(pattern: string, resource: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return resource.startsWith(pattern.slice(0, -1));
  return pattern === resource;
}

export interface GrantMatch {
  /** the authorization detail that matched the action (if any) */
  detail: AuthorizationDetail | null;
  actionMatch: boolean;
  resourceMatch: boolean;
  /** null when the grant has no amount constraint or the request carries no amount */
  amountWithin: boolean | null;
  maxAmount: Amount | null;
  counterpartyAllowed: boolean;
}

export function matchGrant(
  grant: CapabilityGrant,
  action: string,
  resource: string,
  amount: Amount | undefined,
  counterparty: DID,
): GrantMatch {
  const detail = grant.authorizationDetails.find((d) => d.actions.includes(action)) ?? null;
  const actionMatch = detail !== null;
  const resourceMatch = detail ? detail.locations.some((loc) => resourceMatches(loc, resource)) : false;
  const maxAmount = detail?.constraints?.maxAmount ?? null;
  let amountWithin: boolean | null = null;
  if (maxAmount && amount) {
    amountWithin = amount.currency === maxAmount.currency && amount.value <= maxAmount.value;
  }
  const allowed = detail?.constraints?.counterparties;
  const counterpartyAllowed = !allowed || allowed.includes(counterparty);
  return { detail, actionMatch, resourceMatch, amountWithin, maxAmount, counterpartyAllowed };
}
