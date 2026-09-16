/**
 * The policy engine: turns (signed request, verifier state, policy) into a
 * structured Decision. Every predicate is evaluated and reported — nothing
 * short-circuits — so the trace shows exactly which evidence held and which
 * did not. ALLOW is the conjunction of all critical checks:
 *
 *   ALLOW = IdentityValid ∧ SignatureValid ∧ Fresh ∧ CredentialsValid ∧ IssuerTrusted
 *         ∧ NotRevoked ∧ AuthorityScopeAllows ∧ PolicySatisfied
 *
 * There is no score. There is no weighting. A reputation signal (verified
 * attestations) is reported as evidence and can be *required* by policy, but
 * it can never compensate for a failed identity, credential, or authority check.
 */
import { hashDocument, fingerprint } from '../crypto/hash';
import { verifyDocument } from '../crypto/data-integrity';
import {
  resolveDidKey,
  resolvePublicKeyForVerificationMethod,
  verificationMethodId,
  shortDid,
} from '../identity/did-key';
import {
  checkCredentialStatus,
  checkValidityWindow,
  credentialHasType,
  verifyCredentialProof,
  type StatusListResolver,
} from '../credentials/verify';
import type { VerifiableCredential } from '../credentials/types';
import { matchGrant, verifyGrantProof } from '../authority/grant';
import type { CapabilityGrant } from '../authority/types';
import { verifyAttestation } from '../receipts/receipts';
import type { ActionRequest } from '../requests/types';
import type { Amount, DID } from '../types';
import { CHECK_META } from './checks';
import { buildExplanation } from './explain';
import type { Check, CheckId, CheckStatus, Decision, EvidenceRefs, Policy } from './types';
import type { NonceCache } from '../verifier/nonce-cache';

export interface GateContext {
  verifierDid: DID;
  policy: Policy;
  now: Date;
  nonceCache: NonceCache;
  resolveStatusList: StatusListResolver;
  /** Called after each check is evaluated; may return a promise (the UI awaits it to animate). */
  onCheck?: (check: Check, index: number, total: number) => void | Promise<void>;
  /** Optional display names for DIDs, used only to make text human-friendly. */
  labels?: Record<DID, string>;
}

/** "Buyer Agent (did:key:z6Mk…abcd)" when a label is known, else the short DID. */
export function labelDid(labels: Record<DID, string> | undefined, did: string): string {
  const name = labels?.[did];
  return name ? name + ' (' + shortDid(did) + ')' : shortDid(did);
}

export const TOTAL_CHECKS = 20;
/** tolerated clock skew when a request's issuedAt is slightly in the future */
const CLOCK_SKEW_MS = 30_000;

function fmtAmount(a: Amount | undefined | null): string {
  if (!a) return 'n/a';
  return a.currency === 'USD' ? '$' + a.value.toLocaleString('en-US') : a.value + ' ' + a.currency;
}

function isSafeString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0 && v.length < 512;
}

export async function evaluate(request: ActionRequest, ctx: GateContext): Promise<Omit<Decision, 'receipt'>> {
  const started = Date.now();
  let waitedMs = 0; // time spent inside onCheck (UI animation) — excluded from durationMs
  const { policy, now } = ctx;
  const req = policy.require;
  const checks: Check[] = [];
  const who = (did: string) => labelDid(ctx.labels, did);

  const push = async (
    id: CheckId,
    status: CheckStatus,
    detail: string,
    evidence: Record<string, string> = {},
    critical = true,
  ) => {
    const meta = CHECK_META[id];
    const check: Check = { id, stage: meta.stage, title: meta.title, status, detail, critical, evidence };
    checks.push(check);
    if (ctx.onCheck) {
      const t0 = Date.now();
      await ctx.onCheck(check, checks.length, TOTAL_CHECKS);
      waitedMs += Date.now() - t0;
    }
    return check;
  };

  const from: DID = isSafeString(request.from) ? request.from : '';
  const amount = request.params?.amount;
  const presentation = request.presentation ?? { credentials: [], grants: [], attestations: [] };
  const credentials: VerifiableCredential[] = Array.isArray(presentation.credentials) ? presentation.credentials : [];
  const grants: CapabilityGrant[] = Array.isArray(presentation.grants) ? presentation.grants : [];
  const attestations = Array.isArray(presentation.attestations) ? presentation.attestations : [];

  // ───────────────────────── identity ─────────────────────────
  const resolved = resolveDidKey(from);
  const declaredVm = request.proof?.verificationMethod ?? '';
  const vmBelongsToFrom = resolved !== null && declaredVm === verificationMethodId(from);
  if (!resolved) {
    await push('IDENTITY_RESOLVED', 'fail', 'from is not a resolvable did:key: ' + (from || '(empty)'), { from });
  } else if (!vmBelongsToFrom) {
    await push(
      'IDENTITY_RESOLVED',
      'fail',
      'Proof names verification method ' + declaredVm + ' which does not belong to ' + who(from) + '. The signer is not the claimed identity.',
      { from, verificationMethod: declaredVm },
    );
  } else {
    await push(
      'IDENTITY_RESOLVED',
      'pass',
      who(from) + ' resolves to Ed25519 key ' + fingerprint(resolved.publicKey) + '; proof names that key.',
      { from, keyFingerprint: fingerprint(resolved.publicKey), verificationMethod: declaredVm },
    );
  }

  if (req.audienceMatch) {
    const ok = request.to === ctx.verifierDid;
    await push(
      'REQUEST_AUDIENCE_MATCH',
      ok ? 'pass' : 'fail',
      ok
        ? 'Request is addressed to this verifier (' + who(ctx.verifierDid) + ').'
        : 'Request is addressed to ' + who(String(request.to)) + ', not this verifier (' + who(ctx.verifierDid) + ').',
      { to: String(request.to), verifier: ctx.verifierDid },
    );
  } else {
    await push('REQUEST_AUDIENCE_MATCH', 'skip', 'Policy does not require an audience check.', {}, false);
  }

  // ───────────────────────── signature ─────────────────────────
  const requestHash = hashDocument(request);
  if (req.identityProof) {
    const sig = verifyDocument(request, resolvePublicKeyForVerificationMethod);
    const ok = sig.valid && vmBelongsToFrom;
    await push(
      'REQUEST_SIGNATURE_VALID',
      ok ? 'pass' : 'fail',
      ok
        ? 'Ed25519 signature over the JCS-canonical request verifies under ' + who(from) + '’s key.'
        : sig.code === 'SIGNATURE_MISMATCH'
          ? 'Signature does NOT verify under ' + who(from) + '’s key. Whoever sent this does not hold that private key (or altered the request after signing).'
          : sig.reason,
      { requestHash, verificationMethod: declaredVm, code: sig.code },
    );
  } else {
    await push('REQUEST_SIGNATURE_VALID', 'skip', 'Policy does not require identity proof (unsafe; demo only).', { requestHash }, false);
  }

  // ───────────────────────── freshness ─────────────────────────
  {
    const issued = Date.parse(request.issuedAt);
    const expires = Date.parse(request.expiresAt);
    const ageMs = now.getTime() - issued;
    const maxAgeMs = req.requestMaxAgeSeconds * 1000;
    const tooOld = Number.isNaN(issued) || ageMs > maxAgeMs;
    const expired = Number.isNaN(expires) || now.getTime() >= expires;
    const future = !Number.isNaN(issued) && issued - now.getTime() > CLOCK_SKEW_MS;
    const ageText = Number.isNaN(issued) ? 'unparseable issuedAt' : (ageMs / 1000).toFixed(1) + 's old';
    if (tooOld || expired || future) {
      await push(
        'REQUEST_FRESH',
        'fail',
        (future
          ? 'issuedAt is in the future beyond clock skew.'
          : 'Request is ' + ageText + (tooOld ? ' (policy max ' + req.requestMaxAgeSeconds + 's)' : '') + (expired ? '; it expired at ' + request.expiresAt : '') + '.') +
          ' Stale requests are rejected to defeat replay.',
        { issuedAt: String(request.issuedAt), expiresAt: String(request.expiresAt), maxAgeSeconds: String(req.requestMaxAgeSeconds) },
      );
    } else {
      await push('REQUEST_FRESH', 'pass', 'Request is ' + ageText + ' (policy max ' + req.requestMaxAgeSeconds + 's) and not expired.', {
        issuedAt: request.issuedAt,
        expiresAt: request.expiresAt,
      });
    }
  }

  const nonce = String(request.nonce ?? '');
  if (req.rejectReusedNonce) {
    const seen = ctx.nonceCache.get(nonce);
    if (!nonce) {
      await push('NONCE_UNSEEN', 'fail', 'Request carries no nonce.', {});
    } else if (seen) {
      await push(
        'NONCE_UNSEEN',
        'fail',
        'Nonce ' + nonce + ' was already consumed at ' + new Date(seen.firstSeenAt).toISOString() + ' — this is a replayed envelope.',
        { nonce, firstSeenAt: new Date(seen.firstSeenAt).toISOString() },
      );
    } else {
      await push('NONCE_UNSEEN', 'pass', 'Nonce ' + nonce + ' has not been seen by this verifier.', { nonce });
    }
  } else {
    await push('NONCE_UNSEEN', 'skip', 'Policy does not track nonces.', {}, false);
  }

  // ───────────────────────── credential ─────────────────────────
  const matched: VerifiableCredential[] = [];
  const missingTypes: string[] = [];
  const wrongSubject: string[] = [];
  for (const type of req.credentialTypes) {
    const ofType = credentials.filter((vc) => credentialHasType(vc, type));
    const aboutFrom = ofType.find((vc) => vc.credentialSubject?.id === from);
    if (aboutFrom) matched.push(aboutFrom);
    else if (ofType.length) wrongSubject.push(type + ' (about ' + who(String(ofType[0].credentialSubject?.id)) + ')');
    else missingTypes.push(type);
  }
  if (req.credentialTypes.length === 0) {
    await push('CREDENTIAL_PRESENT', 'skip', 'Policy requires no credential types.', {}, false);
  } else if (missingTypes.length || wrongSubject.length) {
    await push(
      'CREDENTIAL_PRESENT',
      'fail',
      (missingTypes.length ? 'Missing credential type(s): ' + missingTypes.join(', ') + '. ' : '') +
        (wrongSubject.length ? 'Presented credential is about a different subject: ' + wrongSubject.join(', ') + '.' : ''),
      { required: req.credentialTypes.join(','), presented: String(credentials.length) },
    );
  } else {
    await push(
      'CREDENTIAL_PRESENT',
      'pass',
      matched.map((vc) => vc.type.filter((t) => t !== 'VerifiableCredential').join('/') + ' issued by ' + who(vc.issuer)).join('; ') + ' — subject is ' + who(from) + '.',
      Object.fromEntries(matched.map((vc, i) => ['credential' + i, vc.id])),
    );
  }

  const credEvidence = Object.fromEntries(matched.map((vc, i) => ['credential' + i, vc.id]));
  if (matched.length === 0) {
    const reason = req.credentialTypes.length === 0 ? 'No credential required by policy.' : 'Skipped — no matching credential to verify (CREDENTIAL_PRESENT failed).';
    await push('CREDENTIAL_SIGNATURE_VALID', 'skip', reason, {}, false);
    await push('CREDENTIAL_VALIDITY_WINDOW', 'skip', reason, {}, false);
    await push('CREDENTIAL_ISSUER_TRUSTED', 'skip', reason, {}, false);
    await push('CREDENTIAL_NOT_REVOKED', 'skip', reason, {}, false);
  } else {
    const proofs = matched.map((vc) => ({ vc, r: verifyCredentialProof(vc) }));
    const bad = proofs.filter((p) => !p.r.valid);
    await push(
      'CREDENTIAL_SIGNATURE_VALID',
      bad.length ? 'fail' : 'pass',
      bad.length
        ? bad
            .map((p) =>
              p.r.proof.valid && !p.r.issuerMatchesSigner
                ? 'Credential ' + p.vc.id + ' claims issuer ' + who(p.vc.issuer) + ' but was signed by ' + who(String(p.r.signer)) + '.'
                : 'Credential ' + p.vc.id + ': ' + p.r.proof.reason,
            )
            .join(' ')
        : 'Issuer ' + who(matched[0].issuer) + '’s Ed25519 proof (eddsa-jcs-2022) verifies; the credential is byte-for-byte what the issuer signed.',
      { ...credEvidence, code: bad[0]?.r.proof.code ?? 'VALID' },
    );

    const windows = matched.map((vc) => ({ vc, w: checkValidityWindow(vc, now) }));
    const inactive = windows.filter((x) => !x.w.active);
    await push(
      'CREDENTIAL_VALIDITY_WINDOW',
      inactive.length ? 'fail' : 'pass',
      inactive.length
        ? inactive.map((x) => 'Credential ' + x.vc.id + (x.w.expired ? ' expired at ' + x.w.validUntil : ' is not valid until ' + x.w.validFrom)).join('; ')
        : 'Valid from ' + windows[0].w.validFrom + (windows[0].w.validUntil ? ' until ' + windows[0].w.validUntil : ' (no expiry)') + '.',
      { ...credEvidence, now: now.toISOString() },
    );

    // ───────────────────────── issuer ─────────────────────────
    const untrusted = matched.filter((vc) => !req.trustedIssuers.includes(vc.issuer));
    await push(
      'CREDENTIAL_ISSUER_TRUSTED',
      untrusted.length ? 'fail' : 'pass',
      untrusted.length
        ? 'Issuer ' + who(untrusted[0].issuer) + ' is NOT in this verifier’s trusted-issuer list (' + req.trustedIssuers.length + ' trusted). A valid signature from an untrusted issuer proves nothing.'
        : 'Issuer ' + who(matched[0].issuer) + ' is in this verifier’s trusted-issuer list.',
      { ...credEvidence, issuer: matched[0].issuer, trustedIssuers: req.trustedIssuers.join(',') },
    );

    // ───────────────────────── revocation ─────────────────────────
    if (req.notRevoked) {
      const statuses = matched.map((vc) => ({ vc, s: checkCredentialStatus(vc, ctx.resolveStatusList) }));
      const notOk = statuses.filter((x) => !x.s.ok);
      const first = statuses[0].s;
      await push(
        'CREDENTIAL_NOT_REVOKED',
        notOk.length ? 'fail' : 'pass',
        notOk.length ? notOk.map((x) => x.s.reason).join('; ') : first.reason,
        {
          ...credEvidence,
          statusList: matched[0].credentialStatus?.statusListCredential ?? 'none',
          statusListIndex: matched[0].credentialStatus?.statusListIndex ?? 'none',
          ...(first.listUpdatedAt ? { statusListPublishedAt: first.listUpdatedAt } : {}),
        },
      );
    } else {
      await push('CREDENTIAL_NOT_REVOKED', 'skip', 'Policy does not require a revocation check.', credEvidence, false);
    }
  }

  // ───────────────────────── authority ─────────────────────────
  const agentGrants = grants.filter((g) => g.agent === from);
  const grant = agentGrants.find((g) => g.authorizationDetails?.some((d) => d.actions?.includes(request.action))) ?? agentGrants[0];
  const grantEvidence: Record<string, string> = grant ? { grant: grant.id, principal: grant.principal } : {};
  if (!grant) {
    const reason = grants.length ? 'Presented grant(s) are for a different agent, not ' + who(from) + '.' : 'No capability grant presented. Identity alone confers no authority.';
    await push('AUTHORITY_PRESENT', 'fail', reason, { presentedGrants: String(grants.length) });
    for (const id of ['AUTHORITY_SIGNATURE_VALID', 'AUTHORITY_PRINCIPAL_BOUND', 'AUTHORITY_ACTION_MATCH', 'AUTHORITY_RESOURCE_MATCH', 'AUTHORITY_VALIDITY_WINDOW', 'AUTHORITY_AMOUNT_WITHIN_GRANT'] as CheckId[]) {
      await push(id, 'skip', 'Skipped — no grant to evaluate (AUTHORITY_PRESENT failed).', {}, false);
    }
  } else {
    await push('AUTHORITY_PRESENT', 'pass', 'Grant ' + grant.id + ' from principal ' + who(grant.principal) + ' to ' + who(from) + '.', grantEvidence);

    const gp = verifyGrantProof(grant);
    await push(
      'AUTHORITY_SIGNATURE_VALID',
      gp.valid ? 'pass' : 'fail',
      gp.valid
        ? 'Principal ' + who(grant.principal) + '’s Ed25519 proof (capabilityDelegation) verifies; the grant is unaltered.'
        : gp.proof.valid && !gp.principalMatchesSigner
          ? 'Grant claims principal ' + who(grant.principal) + ' but was signed by ' + who(String(gp.signer)) + '.'
          : 'Grant proof invalid: ' + gp.proof.reason,
      { ...grantEvidence, code: gp.proof.code },
    );

    if (req.authority.principalMustBeCredentialController) {
      const controller = matched[0]?.credentialSubject?.controller;
      const ok = isSafeString(controller) && controller === grant.principal;
      await push(
        'AUTHORITY_PRINCIPAL_BOUND',
        ok ? 'pass' : 'fail',
        ok
          ? 'Grant principal ' + who(grant.principal) + ' equals the controller attested in the credential.'
          : matched.length === 0
            ? 'No verified credential attests a controller for this agent, so the grant principal cannot be bound.'
            : 'Grant principal ' + who(grant.principal) + ' is not the controller attested by the credential (' + (isSafeString(controller) ? who(controller) : 'none') + ').',
        { ...grantEvidence, attestedController: isSafeString(controller) ? controller : 'none' },
      );
    } else {
      await push('AUTHORITY_PRINCIPAL_BOUND', 'skip', 'Policy does not bind grant principal to credential controller.', grantEvidence, false);
    }

    const m = matchGrant(grant, request.action, request.resource, amount, ctx.verifierDid);
    await push(
      'AUTHORITY_ACTION_MATCH',
      m.actionMatch ? 'pass' : 'fail',
      m.actionMatch
        ? 'Action "' + request.action + '" is listed in the grant (' + m.detail!.actions.join(', ') + ').'
        : 'Action "' + request.action + '" is not delegated. Grant allows: ' + grant.authorizationDetails.flatMap((d) => d.actions).join(', ') + '.',
      { ...grantEvidence, action: request.action },
    );
    await push(
      'AUTHORITY_RESOURCE_MATCH',
      m.resourceMatch ? 'pass' : 'fail',
      m.resourceMatch
        ? 'Resource "' + request.resource + '" matches ' + m.detail!.locations.join(' | ') + '.'
        : 'Resource "' + request.resource + '" does not match any grant location' + (m.detail ? ' (' + m.detail.locations.join(' | ') + ')' : '') + '.',
      { ...grantEvidence, resource: request.resource },
    );
    const gw = checkValidityWindow(grant, now);
    await push(
      'AUTHORITY_VALIDITY_WINDOW',
      gw.active ? 'pass' : 'fail',
      gw.active
        ? 'Grant valid from ' + gw.validFrom + ' until ' + gw.validUntil + '.'
        : gw.expired
          ? 'Grant EXPIRED at ' + gw.validUntil + '. Delegated authority is time-boxed; the principal must renew it.'
          : 'Grant is not valid until ' + gw.validFrom + '.',
      { ...grantEvidence, validUntil: String(grant.validUntil), now: now.toISOString() },
    );
    if (!m.detail) {
      await push('AUTHORITY_AMOUNT_WITHIN_GRANT', 'fail', 'No matching authorization detail to evaluate an amount against.', grantEvidence);
    } else if (m.amountWithin === null) {
      const unbounded = !m.maxAmount;
      await push(
        'AUTHORITY_AMOUNT_WITHIN_GRANT',
        unbounded ? 'warn' : 'pass',
        unbounded ? 'Grant carries no amount constraint (unbounded delegation — flagged).' : 'Request carries no amount; grant cap is ' + fmtAmount(m.maxAmount) + '.',
        { ...grantEvidence, maxAmount: fmtAmount(m.maxAmount) },
        false,
      );
    } else {
      await push(
        'AUTHORITY_AMOUNT_WITHIN_GRANT',
        m.amountWithin ? 'pass' : 'fail',
        m.amountWithin
          ? 'Requested ' + fmtAmount(amount) + ' ≤ delegated cap ' + fmtAmount(m.maxAmount) + '.'
          : 'Requested ' + fmtAmount(amount) + ' EXCEEDS the delegated cap of ' + fmtAmount(m.maxAmount) + '. Identity and credential are valid, but the principal never authorized this much.',
        { ...grantEvidence, requested: fmtAmount(amount), maxAmount: fmtAmount(m.maxAmount) },
      );
    }
  }

  // ───────────────────────── history ─────────────────────────
  {
    const results = attestations.map((a) => ({ a, r: verifyAttestation(a) }));
    const verified = results.filter((x) => x.r.valid && x.a.subject === from && x.a.issuer !== from);
    const invalid = results.filter((x) => !x.r.valid);
    const attesters = new Set(verified.map((x) => x.a.issuer));
    const enough = verified.length >= req.minVerifiedAttestations;
    const status: CheckStatus = !enough ? 'fail' : invalid.length ? 'warn' : 'pass';
    await push(
      'HISTORY_ATTESTATIONS_VERIFIED',
      status,
      verified.length + ' of ' + attestations.length + ' presented attestation(s) verified' +
        (attesters.size ? ' from ' + attesters.size + ' distinct counterpart' + (attesters.size === 1 ? 'y' : 'ies') : '') +
        (invalid.length ? '; ' + invalid.length + ' failed signature verification' : '') +
        ' (policy minimum: ' + req.minVerifiedAttestations + '). Evidence only — cannot override failed checks.',
      Object.fromEntries(verified.map((x, i) => ['attestation' + i, x.a.id])),
      req.minVerifiedAttestations > 0,
    );
  }

  // ───────────────────────── policy ─────────────────────────
  if (req.authority.maxAmount && amount) {
    const cap = req.authority.maxAmount;
    const ok = amount.currency === cap.currency && amount.value <= cap.value;
    await push(
      'POLICY_AMOUNT_WITHIN_LIMIT',
      ok ? 'pass' : 'fail',
      ok ? 'Requested ' + fmtAmount(amount) + ' ≤ verifier cap ' + fmtAmount(cap) + '.' : 'Requested ' + fmtAmount(amount) + ' exceeds this verifier’s own cap of ' + fmtAmount(cap) + '.',
      { requested: fmtAmount(amount), policyMaxAmount: fmtAmount(cap) },
    );
  } else {
    await push('POLICY_AMOUNT_WITHIN_LIMIT', 'skip', req.authority.maxAmount ? 'Request carries no amount.' : 'Verifier sets no cap of its own.', {}, false);
  }

  const actionGoverned = policy.action === '*' || policy.action === request.action;
  const criticalFailures = checks.filter((c) => c.critical && c.status === 'fail');
  const allow = actionGoverned && criticalFailures.length === 0;
  await push(
    'POLICY_SATISFIED',
    allow ? 'pass' : 'fail',
    !actionGoverned
      ? 'Policy ' + policy.policyId + ' governs "' + policy.action + '", not "' + request.action + '".'
      : allow
        ? 'All ' + checks.filter((c) => c.critical).length + ' required predicates of ' + policy.policyId + ' passed.'
        : criticalFailures.length + ' required predicate(s) failed: ' + criticalFailures.map((c) => c.id).join(', ') + '.',
    { policyId: policy.policyId, policyVersion: String(policy.version) },
  );

  const failedChecks = checks.filter((c) => c.status === 'fail');
  const evidence: EvidenceRefs = {
    presentedBy: from,
    requestHash,
    credentialIds: credentials.map((c) => c.id),
    grantIds: grants.map((g) => g.id),
    attestationIds: attestations.map((a) => a.id),
    statusListIds: Array.from(new Set(credentials.map((c) => c.credentialStatus?.statusListCredential).filter((x): x is string => !!x))),
    issuerDids: Array.from(new Set(credentials.map((c) => c.issuer))),
    principalDids: Array.from(new Set(grants.map((g) => g.principal))),
  };

  const partial: Omit<Decision, 'receipt' | 'explanation'> = {
    allow,
    decision: allow ? 'ALLOW' : 'DENY',
    policyId: policy.policyId,
    policyHash: hashDocument(policy),
    verifier: ctx.verifierDid,
    subject: from,
    action: request.action,
    resource: request.resource,
    ...(amount ? { amount } : {}),
    requestId: request.id,
    requestHash,
    checks,
    failedChecks,
    evidence,
    timestamp: now.toISOString(),
    durationMs: Date.now() - started - waitedMs,
  };
  return { ...partial, explanation: buildExplanation(partial, request, ctx.labels) };
}

