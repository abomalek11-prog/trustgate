import { expect } from 'vitest';
import type { Decision, CheckId } from '@/lib/policy/types';
import { createDemoWorld, type DemoWorld } from '@/lib/demo/world';
import { buildRequestFor, presentationFor, type BuildRequestOptions } from '@/lib/demo/scenarios';

/** A fixed "now" inside every fixture's validity window, so tests never drift with the wall clock. */
export const NOW = new Date('2026-10-01T12:00:00Z');

export function world(): DemoWorld {
  return createDemoWorld();
}

export function request(w: DemoWorld, o: Omit<BuildRequestOptions, 'now'> & { now?: Date }) {
  return buildRequestFor(w, { ...o, now: o.now ?? NOW });
}

export { presentationFor };

export function status(d: Decision, id: CheckId) {
  const c = d.checks.find((x) => x.id === id);
  if (!c) throw new Error('check not found: ' + id);
  return c.status;
}

export function expectDeny(d: Decision, ...failing: CheckId[]) {
  expect(d.allow).toBe(false);
  expect(d.decision).toBe('DENY');
  for (const id of failing) expect(status(d, id), id).toBe('fail');
  expect(d.failedChecks.map((c) => c.id)).toEqual(expect.arrayContaining(failing));
  expect(d.explanation.startsWith('DENY')).toBe(true);
}

export function expectAllow(d: Decision) {
  expect(d.decision).toBe('ALLOW');
  expect(d.allow).toBe(true);
  expect(d.failedChecks).toHaveLength(0);
  expect(d.explanation.startsWith('ALLOW')).toBe(true);
  expect(d.receipt?.decision).toBe('ALLOW');
}
