/**
 * Scoped, delegated authority.
 *
 * A principal (the entity that would be on the hook — an owner, a treasury, a
 * team) signs a Capability Grant that says: "agent X may perform ACTIONS on
 * LOCATIONS subject to CONSTRAINTS until validUntil". The structure borrows
 * `authorization_details` from OAuth 2.0 Rich Authorization Requests (RFC 9396):
 * structured, fine-grained authorization instead of a flat scope string.
 *
 * Authority is deliberately SEPARATE from identity and reputation: a perfectly
 * verified, highly attested agent still has zero purchasing power without a grant.
 */
import type { Amount, DID, ISODateTime, Signed } from '../types';

export interface AuthorizationDetail {
  /** RFC 9396 `type`: the kind of authorization, e.g. "purchase" */
  type: string;
  /** Actions permitted within this type, e.g. ["purchase"] */
  actions: string[];
  /** Resource patterns; `*` is a wildcard suffix, e.g. "vendor:*" */
  locations: string[];
  constraints?: {
    maxAmount?: Amount;
    /** Optional allow-list of counterparty DIDs this authority may be used with */
    counterparties?: DID[];
  };
}

export interface UnsignedCapabilityGrant {
  '@context': string[];
  id: string;
  type: ['CapabilityGrant'];
  /** who delegates (signs) */
  principal: DID;
  /** who receives the authority */
  agent: DID;
  authorizationDetails: AuthorizationDetail[];
  validFrom: ISODateTime;
  validUntil: ISODateTime;
  /** uniqueness salt so two otherwise-identical grants differ */
  nonce: string;
}

export type CapabilityGrant = Signed<UnsignedCapabilityGrant>;
