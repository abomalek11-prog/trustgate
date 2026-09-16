/**
 * A Verifier is the receiving agent's trust gate. It owns:
 *   - its own keypair (to sign decision receipts),
 *   - its policy (verifier-local; editable),
 *   - a nonce cache (replay defense),
 *   - a view of issuer status lists (revocation).
 *
 * `gate()` evaluates a signed ActionRequest and returns a Decision with a
 * signed receipt. It is the only entry point the demo UI and the API use.
 */
import type { StatusListCredential } from '../credentials/types';
import { evaluate, type GateContext } from '../policy/engine';
import type { Check, Decision, Policy } from '../policy/types';
import { issueDecisionReceipt } from '../receipts/receipts';
import type { ActionRequest } from '../requests/types';
import type { DID, KeyPair } from '../types';
import { NonceCache } from './nonce-cache';

export interface VerifierOptions {
  did: DID;
  keys: KeyPair;
  policy: Policy;
  /** Live lookup of issuer status lists (simulates fetching the issuer's published list). */
  resolveStatusList?: (id: string) => StatusListCredential | undefined;
  /** Display names for DIDs (presentation only). */
  labels?: Record<DID, string>;
}

export interface GateOptions {
  now?: Date;
  onCheck?: GateContext['onCheck'];
  /** Evaluate without consuming the nonce (what-if mode for the policy editor). */
  dryRun?: boolean;
  /** Evaluate under a different policy than the verifier's current one (API what-if). */
  policy?: Policy;
}

export class Verifier {
  readonly did: DID;
  readonly keys: KeyPair;
  policy: Policy;
  readonly nonceCache = new NonceCache();
  private statusLists = new Map<string, StatusListCredential>();
  private externalResolver?: (id: string) => StatusListCredential | undefined;
  labels: Record<DID, string>;
  readonly decisions: Decision[] = [];

  constructor(opts: VerifierOptions) {
    this.did = opts.did;
    this.keys = opts.keys;
    this.policy = opts.policy;
    this.externalResolver = opts.resolveStatusList;
    this.labels = opts.labels ?? {};
  }

  /** Cache a status list locally (e.g. fetched from an issuer endpoint). */
  registerStatusList(list: StatusListCredential): void {
    this.statusLists.set(list.id, list);
  }

  resolveStatusList = (id: string): StatusListCredential | undefined => {
    return this.externalResolver?.(id) ?? this.statusLists.get(id);
  };

  setPolicy(policy: Policy): void {
    this.policy = policy;
  }

  async gate(request: ActionRequest, opts: GateOptions = {}): Promise<Decision> {
    const now = opts.now ?? new Date();
    const policy = opts.policy ?? this.policy;
    this.nonceCache.prune(now.getTime());
    const partial = await evaluate(request, {
      verifierDid: this.did,
      policy,
      now,
      nonceCache: this.nonceCache,
      resolveStatusList: this.resolveStatusList,
      onCheck: opts.onCheck,
      labels: this.labels,
    });

    // Consume the nonce only for authentically signed requests, so an attacker
    // cannot burn a victim's nonce with a forged envelope.
    const sigOk = partial.checks.find((c: Check) => c.id === 'REQUEST_SIGNATURE_VALID')?.status === 'pass';
    if (sigOk && !opts.dryRun && request.nonce) {
      this.nonceCache.add(request.nonce, now.getTime(), policy.require.requestMaxAgeSeconds * 1000 * 2);
    }

    const receipt = issueDecisionReceipt({
      verifier: { did: this.did, secretKey: this.keys.secretKey },
      id: 'urn:uuid:' + crypto.randomUUID(),
      subject: partial.subject,
      requestId: partial.requestId,
      requestHash: partial.requestHash,
      action: partial.action,
      resource: partial.resource,
      ...(partial.amount ? { amount: partial.amount } : {}),
      decision: partial.decision,
      policyId: partial.policyId,
      policyHash: partial.policyHash,
      checks: partial.checks.map((c) => ({ id: c.id, status: c.status })),
      issuedAt: now.toISOString(),
    });

    const decision: Decision = { ...partial, receipt };
    if (!opts.dryRun) this.decisions.unshift(decision);
    return decision;
  }
}
