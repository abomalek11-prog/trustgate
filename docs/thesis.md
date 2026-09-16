# Two-year thesis on agent identity and reputation

_269 words. Source of truth: `lib/thesis.ts` (also rendered at `/architecture`)._

Over the next two years, agent identity will split into three layers: cryptographic identity, portable evidence, and local trust policy.

A durable agent identity should not be a username owned by one platform. It should be a key-bound identifier that can prove control: the identifier is the public key, and control is a signature. Reputation should not be a global score either; it should be a collection of signed, contextual claims and receipts — who observed what, under which conditions, and when. Authority must remain separate from reputation. A highly reputable agent still should not be able to spend money, access a dataset, or sign a contract unless a principal explicitly delegated that capability within clear constraints: action, resource, amount, time.

The winning trust layer will therefore look less like a social rating system and more like a programmable verification fabric. Agents present credentials and capability grants; counterparties verify signatures, status, freshness, provenance, and scope; then each verifier applies its own policy. This keeps trust interoperable without forcing everyone to agree on one universal definition of "good." Revocation is a signed artifact, not a support ticket. Every decision leaves a signed receipt, so trust compounds as evidence rather than as a number that can be gamed.

At scale, the valuable primitive is not "Agent X has score 92." It is: "Agent X controls this identity, these issuers attest these facts, this principal delegated this authority until this time, these counterparties signed these receipts, and my policy accepts that evidence for this exact action." That model crosses companies, frameworks, and agent runtimes while staying explainable, revocable, and resistant to spoofing.
