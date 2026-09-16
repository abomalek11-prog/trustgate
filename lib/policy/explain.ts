/**
 * Turns a structured decision into one or two plain-English sentences that a
 * non-crypto judge understands in seconds. The machine-readable checks remain
 * the source of truth; this is a rendering of them.
 */
import { shortDid } from '../identity/did-key';
import type { DID } from '../types';
import type { ActionRequest } from '../requests/types';
import type { Amount } from '../types';
import type { Check, Decision } from './types';

function money(a?: Amount): string {
  if (!a) return 'an unpriced action';
  return a.currency === 'USD' ? '$' + a.value.toLocaleString('en-US') : a.value + ' ' + a.currency;
}

type Who = (did: string) => string;
const HEADLINES: Partial<Record<Check['id'], (d: Omit<Decision, 'receipt' | 'explanation'>, c: Check, who: Who) => string>> = {
  IDENTITY_RESOLVED: (d, _c, who) => 'The requester’s identity could not be bound to a key: ' + who(d.subject) + ' is not proven by this request.',
  REQUEST_SIGNATURE_VALID: (d, _c, who) =>
    'The request claims to come from ' + who(d.subject) + ', but its signature does not verify under that DID’s public key. Whoever sent it does not control the real private key — this is a spoofed identity.',
  REQUEST_FRESH: () => 'The request is stale: it was issued too long ago (or has expired). Old captured requests cannot be replayed.',
  NONCE_UNSEEN: () => 'This exact request envelope was already processed — its nonce was consumed earlier. Replay rejected.',
  CREDENTIAL_PRESENT: () => 'The requester did not present the credential this verifier requires about itself.',
  CREDENTIAL_SIGNATURE_VALID: () =>
    'The presented credential’s issuer signature does not verify: the credential was altered after issuance (or forged). Tampered evidence is rejected.',
  CREDENTIAL_VALIDITY_WINDOW: () => 'The presented credential is outside its validity window.',
  CREDENTIAL_ISSUER_TRUSTED: (_d, c, who) =>
    'The credential is cryptographically valid, but its issuer (' + who(c.evidence.issuer ?? '') + ') is not one this verifier trusts. Valid ≠ trusted: trust in issuers is a local policy decision.',
  CREDENTIAL_NOT_REVOKED: () => 'The credential has been revoked by its issuer (signed status list). It was valid once; it is not valid now.',
  AUTHORITY_PRESENT: () => 'No capability grant was presented. A verified identity still has no authority to act until a principal delegates it.',
  AUTHORITY_SIGNATURE_VALID: () => 'The capability grant’s signature does not verify: the grant was altered or not actually signed by its principal.',
  AUTHORITY_PRINCIPAL_BOUND: () => 'The grant was not issued by the principal that the credential attests as this agent’s controller.',
  AUTHORITY_ACTION_MATCH: (d) => 'The principal never delegated the action “' + d.action + '” to this agent.',
  AUTHORITY_RESOURCE_MATCH: (d) => 'The delegated authority does not cover the resource “' + d.resource + '”.',
  AUTHORITY_VALIDITY_WINDOW: () => 'The capability grant has expired. Delegated authority is time-boxed and must be renewed by the principal.',
  AUTHORITY_AMOUNT_WITHIN_GRANT: (d, c) =>
    'Identity and credential are valid, but the requested ' + money(d.amount) + ' exceeds the ' + (c.evidence.maxAmount ?? 'delegated') + ' the principal authorized. Valid identity does not mean unlimited authority.',
  HISTORY_ATTESTATIONS_VERIFIED: () => 'The policy requires more verified counterparty attestations than were presented.',
  POLICY_AMOUNT_WITHIN_LIMIT: (d, c) => 'The requested ' + money(d.amount) + ' exceeds this verifier’s own cap of ' + (c.evidence.policyMaxAmount ?? 'its limit') + '.',
  REQUEST_AUDIENCE_MATCH: () => 'The request was addressed to a different verifier.',
  POLICY_SATISFIED: () => 'The policy does not govern this action.',
};

export function buildExplanation(d: Omit<Decision, 'receipt' | 'explanation'>, request: ActionRequest, labels?: Record<DID, string>): string {
  const who: Who = (did) => (labels?.[did] ? labels[did] + ' (' + shortDid(did) + ')' : shortDid(did));
  const failed = d.checks.filter((c) => c.status === 'fail' && c.critical);
  if (d.allow) {
    const cred = d.checks.find((c) => c.id === 'CREDENTIAL_PRESENT');
    const issuer = d.checks.find((c) => c.id === 'CREDENTIAL_ISSUER_TRUSTED');
    const amt = d.checks.find((c) => c.id === 'AUTHORITY_AMOUNT_WITHIN_GRANT');
    const hist = d.checks.find((c) => c.id === 'HISTORY_ATTESTATIONS_VERIFIED');
    const fresh = d.checks.find((c) => c.id === 'REQUEST_FRESH');
    const parts = [
      who(d.subject) + ' proved control of its key',
      cred?.status === 'pass' ? 'holds a ' + (request.presentation.credentials[0]?.type.filter((t) => t !== 'VerifiableCredential').join('/') ?? 'required') + ' credential from a trusted issuer' + (issuer?.evidence.issuer ? ' (' + who(issuer.evidence.issuer) + ')' : '') + ' that is not revoked' : null,
      amt?.status === 'pass' ? 'and is acting within the authority its principal delegated (' + (amt.evidence.requested ?? '') + ' ≤ ' + (amt.evidence.maxAmount ?? '') + ')' : 'and holds matching delegated authority',
    ].filter(Boolean);
    const tail = [
      fresh?.status === 'pass' ? 'The request is fresh and its nonce is new.' : '',
      hist && hist.evidence && Object.keys(hist.evidence).length ? Object.keys(hist.evidence).length + ' signed counterparty attestation(s) verified as supporting evidence.' : '',
    ]
      .filter(Boolean)
      .join(' ');
    return 'ALLOW — ' + parts.join(', ') + '. ' + tail;
  }
  const first = failed[0] ?? d.checks.find((c) => c.status === 'fail');
  const headline = first ? (HEADLINES[first.id]?.(d, first, who) ?? first.detail) : 'A required predicate failed.';
  const others = failed.filter((c) => c !== first && c.id !== 'POLICY_SATISFIED');
  const passedCount = d.checks.filter((c) => c.status === 'pass').length;
  const more = others.length ? ' Also failed: ' + others.map((c) => c.id).join(', ') + '.' : '';
  return 'DENY — ' + headline + more + ' (' + passedCount + ' other checks passed; a single failed requirement is sufficient to deny.)';
}
