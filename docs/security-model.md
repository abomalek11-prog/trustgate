# Security model, threat model and limitations

## What TrustGate proves

For an `ActionRequest` from agent **A** to verifier **V**, the engine
establishes, in this order, with every predicate reported:

| Stage | Predicate | Mechanism |
| --- | --- | --- |
| Identity | `IDENTITY_RESOLVED` | `from` is a well-formed `did:key`; the proof's `verificationMethod` is that DID's own key (foreign fragments are rejected by the resolver). |
| Identity | `REQUEST_AUDIENCE_MATCH` | `to === V.did` (RFC 8725 §3.9 audience discipline). |
| Signature | `REQUEST_SIGNATURE_VALID` | Ed25519 over `SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(document))` verifies under the key inside `from`. |
| Freshness | `REQUEST_FRESH` | `now − issuedAt ≤ maxAge`, `now < expiresAt`, `issuedAt` not in the future beyond 30 s skew. |
| Freshness | `NONCE_UNSEEN` | V's nonce cache; nonces are consumed only after an authentic signature so forged envelopes cannot burn a victim's nonce. |
| Credential | `CREDENTIAL_PRESENT` | A VC of each required type whose `credentialSubject.id === from`. Borrowed credentials fail here. |
| Credential | `CREDENTIAL_SIGNATURE_VALID` | Issuer proof verifies **and** the signing DID equals the `issuer` field. |
| Credential | `CREDENTIAL_VALIDITY_WINDOW` | `validFrom ≤ now < validUntil`. |
| Issuer | `CREDENTIAL_ISSUER_TRUSTED` | `issuer ∈ policy.trustedIssuers`. Cryptographically valid ≠ trusted. |
| Revocation | `CREDENTIAL_NOT_REVOKED` | Status list fetched, its proof verifies, its issuer equals the credential issuer, bit at `statusListIndex` is clear. Anything missing → fail closed. |
| Authority | `AUTHORITY_PRESENT` … `AUTHORITY_AMOUNT_WITHIN_GRANT` | Grant for `agent === from`; principal proof verifies and signer = principal; `principal === credentialSubject.controller`; action ∈ `actions`; resource matches a `location`; validity window; `amount ≤ maxAmount` with matching currency. |
| History | `HISTORY_ATTESTATIONS_VERIFIED` | Each attestation's proof verifies, `subject === from`, attester ≠ subject; count ≥ policy minimum. Never overrides other stages. |
| Policy | `POLICY_AMOUNT_WITHIN_LIMIT`, `POLICY_SATISFIED` | Verifier-local cap; final conjunction over all critical predicates. |

The decision is signed by V (`DecisionReceipt`) and bound to `requestHash`
and `policyHash`, so a third party can later confirm exactly what was decided
about which bytes under which rules.

## Threats defended (all executable in the Attack Lab and covered by tests)

| Threat | Attacker capability | Defense |
| --- | --- | --- |
| Spoofed identity | Knows the victim's DID and all public documents | Cannot produce a valid Ed25519 signature → `REQUEST_SIGNATURE_VALID` |
| Impersonation via foreign key | Puts its own key id in the proof | `IDENTITY_RESOLVED` (fragment must belong to `from`) |
| Tampered credential | Edits claims after issuance | `CREDENTIAL_SIGNATURE_VALID` (JCS makes any change detectable) |
| Issuer impersonation | Signs with own key, sets `issuer` to a trusted DID | Signer/issuer binding in `verifyCredentialProof` |
| Forged authority | Raises the cap in the grant | `AUTHORITY_SIGNATURE_VALID` |
| Self-delegation | Gets a grant from an unrelated principal | `AUTHORITY_PRINCIPAL_BOUND` |
| Over-scope | Genuine agent exceeds delegated amount/resource/action | `AUTHORITY_*` predicates |
| Expired delegation | Presents an old grant | `AUTHORITY_VALIDITY_WINDOW` |
| Revoked credential | Presents a credential the issuer revoked | `CREDENTIAL_NOT_REVOKED` via signed status list |
| Status-list forgery | Serves a list signed by another key | `verifyStatusList` requires signer = list issuer = credential issuer |
| Untrusted issuer | Buys a valid credential from a credential mill | `CREDENTIAL_ISSUER_TRUSTED` |
| Replay | Resends a captured envelope | `NONCE_UNSEEN`; after the window, `REQUEST_FRESH` |
| Stale delivery | Delays a captured envelope | `REQUEST_FRESH` |
| Cross-verifier replay | Sends V1's envelope to V2 | `REQUEST_AUDIENCE_MATCH` |
| Borrowed credential | Presents someone else's valid VC/grant | `CREDENTIAL_PRESENT`, `AUTHORITY_PRESENT` (subject/agent binding) |
| Reputation laundering | Presents many (even valid) attestations | Attestations are evidence only; cannot bypass any failed predicate |
| Forged attestation | Alters an attestation | Per-attestation proof verification; reported, not counted |
| Algorithm confusion | Sends a proof with another suite | Only `DataIntegrityProof`/`eddsa-jcs-2022` accepted |

## Out of scope / known limitations (deliberately honest)

* **Key custody.** Demo keys are derived from public labels so the demo is
  reproducible; a real deployment uses CSPRNG/HSM keys and never ships them to
  a browser.
* **Transport security.** The envelope is signed, not encrypted. Confidential
  claims would need transport encryption or selective disclosure (BBS+/SD-JWT),
  which we did not implement.
* **did:key only.** No `did:web`/rotation/deactivation. Key rotation needs a
  method with a mutable DID Document.
* **Status list subset.** Uncompressed bitstring, 1024 entries, served from
  memory; a production issuer publishes a GZIP-compressed, ≥131 072-entry list
  over HTTPS with caching.
* **JSON-LD.** Documents follow the VC 2.0 shape and are canonicalized with
  JCS; no JSON-LD expansion/RDF canonicalization is performed. The proof suite
  is `eddsa-jcs-2022`, which is defined for exactly this case.
* **Serverless state.** `/api` state (nonce cache, revocation flags) is
  per-process; the browser demo is the canonical stateful path.
* **Issuer governance, dispute resolution, privacy-preserving proofs and
  blockchain anchoring** are intentionally out of scope: revocation and scoped
  verification matter more than chain usage for this problem.
