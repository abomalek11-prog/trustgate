import { CHECK_META, STAGE_LABEL, STAGE_ORDER } from '@/lib/policy/checks';
import type { CheckId } from '@/lib/policy/types';
import { THESIS, THESIS_WORD_COUNT } from '@/lib/thesis';

const STANDARDS = [
  { name: 'W3C DID Core — did:key', use: 'Agent, issuer and principal identifiers. The identifier embeds the Ed25519 public key; resolution is local and deterministic.', where: 'lib/identity/did-key.ts' },
  { name: 'W3C Verifiable Credentials 2.0', use: 'VerifiedBusinessAgent credentials: @context, type, issuer, validFrom/validUntil, credentialSubject, credentialStatus.', where: 'lib/credentials/' },
  { name: 'W3C Data Integrity — eddsa-jcs-2022', use: 'One proof suite for every signed object: JCS canonicalization → SHA-256 → Ed25519. Credentials, grants, requests, attestations, receipts, status lists.', where: 'lib/crypto/data-integrity.ts' },
  { name: 'W3C Bitstring Status List (subset)', use: 'Issuer-signed revocation. Credential points at index N in a signed bitstring; bit set = revoked. Uncompressed, 1024 entries.', where: 'lib/credentials/status-list.ts' },
  { name: 'RFC 9396 Rich Authorization Requests', use: 'Structured authorization_details in capability grants: type, actions, locations, constraints (maxAmount, counterparties).', where: 'lib/authority/' },
  { name: 'RFC 8785 JSON Canonicalization', use: 'Byte-stable serialization so signatures survive reordering/whitespace. Implemented in ~25 lines with the RFC test vector.', where: 'lib/crypto/canonicalize.ts' },
  { name: 'RFC 8725 JWT BCP (principles)', use: 'Audience checking, algorithm pinning (only eddsa-jcs-2022 accepted), freshness windows, fail-closed verification.', where: 'lib/policy/engine.ts' },
];

const THREATS: Array<{ attack: string; how: string; caught: CheckId }> = [
  { attack: 'Spoofed agent', how: 'Copies a trusted DID + public profile, signs with own key', caught: 'REQUEST_SIGNATURE_VALID' },
  { attack: 'Forged / tampered credential', how: 'Edits credentialSubject after issuance', caught: 'CREDENTIAL_SIGNATURE_VALID' },
  { attack: 'Forged authority', how: 'Rewrites the grant cap without the principal key', caught: 'AUTHORITY_SIGNATURE_VALID' },
  { attack: 'Revoked credential', how: 'Was valid yesterday; issuer set the status bit', caught: 'CREDENTIAL_NOT_REVOKED' },
  { attack: 'Over-scope request', how: 'Genuine agent asks $2,000 against a $500 grant', caught: 'AUTHORITY_AMOUNT_WITHIN_GRANT' },
  { attack: 'Untrusted issuer', how: 'Valid signature from an issuer outside local policy', caught: 'CREDENTIAL_ISSUER_TRUSTED' },
  { attack: 'Replay', how: 'Re-sends a captured, validly signed envelope', caught: 'NONCE_UNSEEN' },
  { attack: 'Stale request', how: 'Delivers an envelope signed minutes ago', caught: 'REQUEST_FRESH' },
  { attack: 'Expired delegation', how: 'Presents a grant whose validUntil has passed', caught: 'AUTHORITY_VALIDITY_WINDOW' },
  { attack: 'Borrowed credential', how: 'Presents someone else’s (valid) credential and grant', caught: 'CREDENTIAL_PRESENT' },
  { attack: 'Identity without authority', how: 'Verified identity, no grant at all', caught: 'AUTHORITY_PRESENT' },
  { attack: 'Self-delegation', how: 'A grant from a principal that is not the attested controller', caught: 'AUTHORITY_PRINCIPAL_BOUND' },
];

function Box({ title, lines, tone }: { title: string; lines: string[]; tone?: 'ok' | 'accent' }) {
  return (
    <div className={'rounded-xl border p-4 bg-surface-2 ' + (tone === 'ok' ? 'border-ok/40' : tone === 'accent' ? 'border-accent/40' : 'border-line-2')}>
      <div className="text-[12px] uppercase tracking-wide font-semibold text-fg-2">{title}</div>
      <ul className="mt-2 space-y-1 text-[12px] text-muted">
        {lines.map((l) => (
          <li key={l}>· {l}</li>
        ))}
      </ul>
    </div>
  );
}

function Arrow() {
  return (
    <div className="hidden lg:flex items-center justify-center text-muted" aria-hidden>
      <svg width="40" height="24" viewBox="0 0 40 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M2 12h32M28 6l6 6-6 6" />
      </svg>
    </div>
  );
}

export function Architecture() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Architecture</h1>
        <p className="text-sm text-fg-2 mt-1 max-w-3xl">
          Identity → Claims → Verification → Policy → Decision Receipt. Each layer is a separate module in <span className="mono">lib/</span>; the UI is a thin shell around the real engine, and the same engine runs in the browser, in the API routes and in the test suite.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_40px_1fr_40px_1fr_40px_1fr_40px_1fr] gap-3 items-stretch">
        <Box title="1 · Identity" lines={['did:key = Ed25519 public key', 'Signer must prove control', 'No registry, no platform account', 'lib/identity']} />
        <Arrow />
        <Box title="2 · Claims" lines={['VC 2.0 credentials from issuers', 'Capability grants from principals', 'Attestations from counterparties', 'All Data-Integrity signed']} />
        <Arrow />
        <Box title="3 · Verification" lines={['Signature (eddsa-jcs-2022)', 'Issuer trust registry', 'Status list / revocation', 'Freshness + nonce', 'Schema & subject binding']} />
        <Arrow />
        <Box title="4 · Policy" lines={['Declarative JSON predicates', 'Required credential types', 'Trusted issuers', 'Action / resource / amount scope', 'Verifier-local caps']} tone="accent" />
        <Arrow />
        <Box title="5 · Decision Receipt" lines={['ALLOW / DENY + checks[]', 'Plain-English explanation', 'Signed by the verifier', 'Bound to request & policy hashes', 'Feeds the subject’s history']} tone="ok" />
      </div>

      <section className="card p-5">
        <h2 className="text-[13px] font-semibold uppercase tracking-wide text-fg-2">Trust decision</h2>
        <p className="mt-2 mono text-[13px] text-fg leading-relaxed">
          ALLOW(action) = IdentityValid ∧ SignatureValid ∧ Fresh ∧ CredentialValid ∧ IssuerTrusted ∧ NotRevoked ∧ ScopeAllows(action, resource, amount, time) ∧ PolicySatisfied
        </p>
        <p className="mt-2 text-sm text-fg-2 max-w-3xl">
          A conjunction, not a weighted sum. Verified counterparty attestations are reported as evidence and can be <em>required</em> by policy, but they can never compensate for a failed identity, credential, revocation or authority check. That rule is enforced by tests (<span className="mono">tests/reputation-cannot-bypass.test.ts</span>).
        </p>
        <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-3 text-[12.5px]">
          {[
            ['Identity', 'Who controls this agent? Possession of the private key behind its did:key.'],
            ['Credentials', 'What signed claims has a trusted issuer made about it? Type, subject, validity, status.'],
            ['Authority', 'What did a principal explicitly delegate? Actions, resources, amount, time, counterparties.'],
            ['Behavioral evidence', 'What have counterparties signed about past actions? Receipts and attestations, each verified.'],
          ].map(([t, d]) => (
            <div key={t} className="rounded-lg border border-line bg-surface-2 p-3">
              <div className="font-medium">{t}</div>
              <div className="text-muted mt-1">{d}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="card p-5 overflow-x-auto">
        <h2 className="text-[13px] font-semibold uppercase tracking-wide text-fg-2">The 20 predicates</h2>
        <table className="mt-3 w-full text-[12.5px]">
          <thead className="text-left text-muted">
            <tr>
              <th className="py-1 pr-4 font-medium">Stage</th>
              <th className="py-1 pr-4 font-medium">Check</th>
              <th className="py-1 font-medium">What it proves</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {STAGE_ORDER.flatMap((stage) =>
              (Object.keys(CHECK_META) as CheckId[])
                .filter((id) => CHECK_META[id].stage === stage)
                .map((id) => (
                  <tr key={id}>
                    <td className="py-1.5 pr-4 text-fg-2 whitespace-nowrap">{STAGE_LABEL[stage]}</td>
                    <td className="py-1.5 pr-4 mono text-[11.5px] whitespace-nowrap">{id}</td>
                    <td className="py-1.5 text-muted">{CHECK_META[id].help}</td>
                  </tr>
                )),
            )}
          </tbody>
        </table>
      </section>

      <section className="card p-5 overflow-x-auto">
        <h2 className="text-[13px] font-semibold uppercase tracking-wide text-fg-2">Threat model — what the Attack Lab executes</h2>
        <table className="mt-3 w-full text-[12.5px]">
          <thead className="text-left text-muted">
            <tr>
              <th className="py-1 pr-4 font-medium">Attack</th>
              <th className="py-1 pr-4 font-medium">What the attacker does</th>
              <th className="py-1 font-medium">Predicate that denies it</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {THREATS.map((t) => (
              <tr key={t.attack}>
                <td className="py-1.5 pr-4 text-fg whitespace-nowrap">{t.attack}</td>
                <td className="py-1.5 pr-4 text-muted">{t.how}</td>
                <td className="py-1.5 mono text-[11.5px] text-bad whitespace-nowrap">{t.caught}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card p-5 overflow-x-auto">
        <h2 className="text-[13px] font-semibold uppercase tracking-wide text-fg-2">Standards used (and where)</h2>
        <table className="mt-3 w-full text-[12.5px]">
          <tbody className="divide-y divide-line">
            {STANDARDS.map((s) => (
              <tr key={s.name}>
                <td className="py-2 pr-4 text-fg whitespace-nowrap align-top">{s.name}</td>
                <td className="py-2 pr-4 text-muted align-top">{s.use}</td>
                <td className="py-2 mono text-[11px] text-fg-2 whitespace-nowrap align-top">{s.where}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-3 text-[12px] text-muted">
          Honest scoping: JSON-LD expansion is not performed (documents are canonicalized with JCS); the status list is uncompressed; did:key only. These are interoperable subsets, labelled as such, not claimed conformance.
        </p>
      </section>

      <section className="card p-5">
        <h2 className="text-[13px] font-semibold uppercase tracking-wide text-fg-2">Two-year thesis <span className="text-muted normal-case tracking-normal font-normal">({THESIS_WORD_COUNT} words)</span></h2>
        <div className="mt-3 space-y-3 text-[14px] leading-relaxed text-fg max-w-3xl">
          {THESIS.split('\n\n').map((p) => (
            <p key={p.slice(0, 24)}>{p}</p>
          ))}
        </div>
      </section>
    </div>
  );
}
