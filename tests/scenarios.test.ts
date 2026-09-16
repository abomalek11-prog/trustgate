/**
 * Every Attack Lab scenario, run through the real engine, must produce the
 * decision and failing predicates it advertises to judges.
 */
import { describe, expect, it } from 'vitest';
import { NOW, world } from './helpers';
import { runScenario, SCENARIOS } from '@/lib/demo/scenarios';
import { verifyDecisionReceipt } from '@/lib/receipts/receipts';

describe('Attack Lab scenarios', () => {
  for (const s of SCENARIOS) {
    it(s.id + ' -> ' + s.expected + (s.expectedFailures.length ? ' (' + s.expectedFailures.join(', ') + ')' : ''), async () => {
      const w = world();
      const run = await runScenario(w, s.id, { now: NOW });
      expect(run.decision.decision).toBe(s.expected);
      const failedIds = run.decision.failedChecks.map((c) => c.id);
      for (const f of s.expectedFailures) expect(failedIds, 'expected ' + f + ' to fail').toContain(f);
      // only the root cause(s) + POLICY_SATISFIED should fail; dependents are skipped
      const unexpected = failedIds.filter((id) => id !== 'POLICY_SATISFIED' && !s.expectedFailures.includes(id));
      expect(unexpected, 'unexpected failures').toEqual([]);
      // every decision (ALLOW or DENY) carries a verifiable receipt
      expect(verifyDecisionReceipt(run.decision.receipt!).valid).toBe(true);
      expect(run.decision.receipt!.decision).toBe(s.expected);
      if (s.id === 'replay') {
        expect(run.priorSteps).toHaveLength(1);
        expect(run.priorSteps[0].decision.decision).toBe('ALLOW');
        expect(run.priorSteps[0].request.nonce).toBe(run.request.nonce);
      }
    });
  }

  it('exactly one scenario is the happy path and the rest are attacks', () => {
    expect(SCENARIOS.filter((s) => !s.attack).map((s) => s.id)).toEqual(['valid']);
    expect(SCENARIOS.filter((s) => s.attack).length).toBeGreaterThanOrEqual(7);
  });
});
