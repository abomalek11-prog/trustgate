/**
 * The "earns trust" loop: every decision produces a signed receipt, and every
 * ALLOWed action earns the requester a fresh counterparty attestation from the
 * verifier. History grows as signed evidence — never as a number.
 */
import type { Decision } from '../policy/types';
import { issueAttestation } from '../receipts/receipts';
import type { ActionRequest } from '../requests/types';
import type { DemoWorld } from './world';
import { findAgentByDid } from './world';

export function recordOutcome(world: DemoWorld, request: ActionRequest, decision: Decision): void {
  const sigOk = decision.checks.find((c) => c.id === 'REQUEST_SIGNATURE_VALID')?.status === 'pass';
  if (!sigOk) return; // an unauthenticated envelope earns nobody anything
  const agent = findAgentByDid(world, decision.subject);
  if (!agent) return;
  if (decision.receipt) agent.history.unshift(decision.receipt);
  if (decision.allow) {
    const verifier = world.agents.procurement;
    agent.attestations = [
      ...agent.attestations,
      issueAttestation({
        attester: { did: verifier.did, secretKey: verifier.keys.secretKey },
        id: 'urn:uuid:' + crypto.randomUUID(),
        subject: agent.did,
        action: request.action,
        resource: request.resource,
        ...(request.params.amount ? { amount: request.params.amount } : {}),
        outcome: 'completed',
        requestHash: decision.requestHash,
        observedAt: decision.timestamp,
        statement: verifier.name + ' executed ' + request.action + ' of ' + (request.params.description ?? request.resource) + ' for ' + agent.name + '.',
      }),
    ];
  }
}
