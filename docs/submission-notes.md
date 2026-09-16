# Submission notes — DOO Builders League: "The Agent That Earns Trust"

**Project:** TrustGate — the agent that earns trust
**Repo:** https://github.com/abomalek11-prog/trustgate · **Live demo:** _(URL)_ · **Loom:** _(URL, optional)_

## What to look at

1. **Trust-gated interaction** — Console (`/`): Buyer Agent → Procurement Agent, $250 → ALLOW; Spoofed Buyer → DENY (signature); Buyer $2,000 → DENY (scope).
2. **Verification trace + machine-readable decision** — every one of the 20 predicates, with evidence pointers; *Raw JSON* drawer shows the signed request, VC, grant, status list, decision and signed receipt.
3. **Attack Lab** — 11 one-click attacks executed against the real verifier: spoofing, tampering, forged authority, revocation, untrusted issuer, replay, stale request, expired delegation, missing authority, borrowed credential.
4. **Policy Editor** — change the cap or trusted issuers and watch the same request flip between ALLOW and DENY.
5. **Agent Directory / Trust Profile** (`/agents`) — identity, credentials (with live verification), delegated authority, behavioral evidence, decision receipts, risk flags; *Challenge: prove control* runs a live proof-of-possession.
6. **Architecture snapshot** — `/architecture`, `docs/architecture.svg`, `docs/architecture.md`: identity → claims → verification → policy → decision receipt.
7. **Tests** — `npm test`: 80+ tests including every failure case.
8. **HTTP API** — `GET /api/demo/request?scenario=spoofed | POST /api/gate` reproduces the cross-agent decision with curl.

## AI tools used

* **Claude (Claude Code)** — implementation assistance across the engine, UI, tests and documentation; code review; test generation; drafting docs.
* **Human decisions** — the trust model (evidence ∧ authority ∧ policy, never a score), policy semantics, which attacks to make first-class, the "one proof suite everywhere" rule, UX flow, deployment shape, and what to leave out.

## Key decisions

* **Trust is a conjunction of verifiable predicates, not a score.** Reputation appears only as counted, individually verified, counterparty-signed attestations — and tests prove it can never bypass a failed identity, credential, revocation or authority check.
* **Four separate evidence classes:** identity (did:key), credentials (VC 2.0 from issuers), authority (principal-signed capability grants with RFC 9396-style constraints), behavioral evidence (signed attestations + decision receipts).
* **Standards where they carry weight, honest subsets where they don't:** W3C DID Core (did:key), VC 2.0 with Data Integrity `eddsa-jcs-2022`, Bitstring Status List (uncompressed subset), RFC 8785 JCS, RFC 9396 authorization details. No claimed conformance beyond what is implemented.
* **Real crypto through a maintained library** (`@noble/ed25519`, `@noble/hashes`); no hand-rolled primitives. JCS is ~25 lines with the RFC test vector.
* **Verifier-local policy is first-class** and editable live; every receipt records the hash of the exact policy that produced it.
* **Revocation and scope are first-class:** issuer-signed status lists; time-boxed, amount-capped, resource-scoped delegations.
* **Reliable demo over infrastructure:** the engine runs in the judge's browser (deterministic synthetic identities, no secrets, no login, no database) and identically in the API routes and tests.

## Out of scope

Production key custody / HSM; issuer governance and discovery; selective disclosure / zero-knowledge proofs; `did:web` and key rotation; encrypted transport; blockchain anchoring; durable multi-instance server state.

## Two-year thesis

See `docs/thesis.md` (269 words) — also rendered at `/architecture`.
