# 90-second demo script (Loom)

Open the live demo at https://trustgate-lemon.vercel.app (Console, `/`). Keep the Decision card and Verification
Trace visible on the right. Speak the bold lines.

| Time | Action on screen | Say |
| --- | --- | --- |
| 0–10s | Console landing; point at the pipeline strip *Identity → Claims → Verification → Policy → Decision Receipt*. | **"Agents can act for us, but today a receiving agent has no standard way to know who the counterparty really is, what it's authorized to do, or whether its claims were revoked. TrustGate is a trust layer for agent-to-agent actions — TLS for agent behaviour."** |
| 10–25s | Click **Agents → Buyer Agent**. Point at the DID, the *VerifiedBusinessAgent* credential (issuer signature ✓, not revoked), the **$500 purchase authority** from Acme, and the two counterparty attestations. Optionally click *Challenge: prove control* (green). | **"Every agent is a did:key — the identifier is its public key. The Buyer holds a signed credential from a trusted registry, a $500 purchase delegation signed by its owner, and signed receipts from past counterparties. Evidence — not a score."** |
| 25–45s | Back to **Console**. Requester = Buyer, amount **$250**, click **Request Action**. Watch the trace stream: identity, signature, freshness, credential, issuer, revocation, authority, history, policy → big green **ALLOW**. Point at *"✓ receipt signature verified"*. | **"The Procurement Agent verifies the signature against the DID, the issuer's proof, the revocation list, the delegation scope, and freshness — twenty predicates. ALLOW, and it signs a receipt that becomes part of the Buyer's history."** |
| 45–65s | Attack Lab → **Spoofed identity** (or select *Spoofed Buyer Agent* and Request Action). Trace shows everything green except **REQUEST_SIGNATURE_VALID** → red **DENY**. Read the explanation. | **"Now a clone copies the Buyer's DID, credential and grant byte-for-byte — but it can't sign with the real private key. Signature check fails. DENY. Everything else it copied still verifies; it simply cannot prove control."** |
| 65–78s | Select **Buyer Agent**, click **$2,000**, Request Action. Identity ✓, credential ✓, revocation ✓ … **AUTHORITY_AMOUNT_WITHIN_GRANT ✗** → **DENY**. | **"Same genuine Buyer, but asking for $2,000 against a $500 delegation. Identity passes, credential passes — authority fails. Valid identity does not mean unlimited authority."** |
| 78–90s | Click **Architecture**; scroll the pipeline boxes and the formula. | **"Identity, claims, verification, policy, signed receipt. The trust decision is portable, cryptographic, revocable and explainable — not a reputation score."** |

## If you have 30 more seconds

* **Policy Editor:** lower *Verifier max amount* to 200 → the $250 ALLOW flips to DENY instantly; tick *Shady Certs* under trusted issuers → the Rogue bot's untrusted-issuer DENY flips to ALLOW. "Trust is local to the verifier's policy."
* **Attack Lab → Revoked credential:** Verdant re-signs its status list; the Buyer is denied until *Restore credential*.
* **Attack Lab → Replayed request:** the original ALLOW, then the identical envelope → `NONCE_UNSEEN` DENY.
* **Raw JSON** on any decision: the signed request envelope, VC, grant, status list, decision and receipt.

## Recording tips

* Use a 1440-px-wide window so the console and trace sit side by side.
* The trace animates ~75 ms per predicate (≈1.5 s per decision). Click the next action as soon as the stamp lands.
* All state is in the browser: reload the page for a clean world.
