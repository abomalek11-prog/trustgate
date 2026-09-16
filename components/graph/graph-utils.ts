import type { Check, CheckId, CheckStatus } from '@/lib/policy/types';

export interface Pt {
  x: number;
  y: number;
}

export interface NodeBox extends Pt {
  w: number;
  h: number;
}

/** Point where the ray from box centre towards `to` exits the box boundary. */
export function anchor(box: NodeBox, to: Pt, pad = 4): Pt {
  const dx = to.x - box.x;
  const dy = to.y - box.y;
  if (dx === 0 && dy === 0) return { x: box.x, y: box.y };
  const hw = box.w / 2 + pad;
  const hh = box.h / 2 + pad;
  const sx = dx !== 0 ? hw / Math.abs(dx) : Number.POSITIVE_INFINITY;
  const sy = dy !== 0 ? hh / Math.abs(dy) : Number.POSITIVE_INFINITY;
  const s = Math.min(sx, sy);
  return { x: box.x + dx * s, y: box.y + dy * s };
}

/** Quadratic path between two boxes with an optional perpendicular bow. */
export function edgePath(a: NodeBox, b: NodeBox, bow = 0): { d: string; mid: Pt } {
  const p1 = anchor(a, b);
  const p2 = anchor(b, a);
  const mx = (p1.x + p2.x) / 2;
  const my = (p1.y + p2.y) / 2;
  const dx = p2.x - p1.x;
  const dy = p2.y - p1.y;
  const len = Math.hypot(dx, dy) || 1;
  const nx = -dy / len;
  const ny = dx / len;
  const cx = mx + nx * bow;
  const cy = my + ny * bow;
  // point on the quadratic at t=0.5 (for the label)
  const mid = { x: 0.25 * p1.x + 0.5 * cx + 0.25 * p2.x, y: 0.25 * p1.y + 0.5 * cy + 0.25 * p2.y };
  return { d: 'M ' + p1.x + ' ' + p1.y + ' Q ' + cx + ' ' + cy + ' ' + p2.x + ' ' + p2.y, mid };
}

export type EdgeTone = 'idle' | 'active' | 'pass' | 'fail' | 'warn' | 'skip';

const RANK: Record<CheckStatus, number> = { fail: 3, warn: 2, pass: 1, skip: 0 };

/** Worst status among the given check ids present in `checks`; undefined when none evaluated yet. */
export function worstStatus(checks: Check[], ids: CheckId[]): CheckStatus | undefined {
  let best: CheckStatus | undefined;
  for (const c of checks) {
    if (!ids.includes(c.id)) continue;
    if (!best || RANK[c.status] > RANK[best]) best = c.status;
  }
  return best;
}

export function toneFor(status: CheckStatus | undefined, active: boolean): EdgeTone {
  if (status) return status;
  return active ? 'active' : 'idle';
}

export const STROKE: Record<EdgeTone, string> = {
  idle: 'var(--color-line-2)',
  active: 'var(--color-accent)',
  pass: 'var(--color-ok)',
  fail: 'var(--color-bad)',
  warn: 'var(--color-warn)',
  skip: 'var(--color-muted)',
};
