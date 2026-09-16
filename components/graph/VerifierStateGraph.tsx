'use client';
import { useTrustGate } from '../store';
import { STROKE, type EdgeTone } from './graph-utils';
import { CHECK_META, STAGE_LABEL, STAGE_ORDER } from '@/lib/policy/checks';
import type { Check, CheckId, Stage } from '@/lib/policy/types';

/**
 * The verifier's internal graph, drawn the way an agent framework (LangGraph
 * et al.) draws a state machine: START -> one node per stage -> conditional
 * edge -> ALLOW | DENY. There is no model call in any node: each node is a
 * deterministic predicate over signed evidence. State = the growing list of
 * Check results; the conditional edge is the conjunction of critical checks.
 */
const NODE_W = 96;
const NODE_H = 44;
const GAP = 14;
const X0 = 90;
const Y = 60;

function stageStatus(checks: Check[], stage: Stage): EdgeTone {
  const items = checks.filter((c) => c.stage === stage);
  if (!items.length) return 'idle';
  if (items.some((c) => c.status === 'fail')) return 'fail';
  if (items.some((c) => c.status === 'warn')) return 'warn';
  if (items.every((c) => c.status === 'skip')) return 'skip';
  return 'pass';
}

export function VerifierStateGraph() {
  const running = useTrustGate((s) => s.running);
  const live = useTrustGate((s) => s.liveChecks);
  const current = useTrustGate((s) => s.current);
  const checks: Check[] = running ? live : current?.decision.checks ?? [];
  const decided = !running && current ? current.decision : null;
  const activeStage = running ? live[live.length - 1]?.stage : undefined;
  const nextStage = running ? STAGE_ORDER[Math.min(STAGE_ORDER.length - 1, (activeStage ? STAGE_ORDER.indexOf(activeStage) : -1) + 1)] : undefined;

  const xOf = (i: number) => X0 + 60 + i * (NODE_W + GAP);
  const lastX = xOf(STAGE_ORDER.length - 1);
  const endX = lastX + NODE_W / 2 + 110;
  const allowTone: EdgeTone = decided ? (decided.allow ? 'pass' : 'idle') : 'idle';
  const denyTone: EdgeTone = decided ? (decided.allow ? 'idle' : 'fail') : running && checks.some((c) => c.status === 'fail' && c.critical) ? 'fail' : 'idle';
  const checkIds = (Object.keys(CHECK_META) as CheckId[]);

  return (
    <svg viewBox={'0 0 ' + (endX + 90) + ' 190'} className="w-full h-auto" role="img" aria-label="Verifier state machine">
      <defs>
        {(Object.keys(STROKE) as EdgeTone[]).map((t) => (
          <marker key={t} id={'sg-arrow-' + t} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" fill={STROKE[t]} />
          </marker>
        ))}
      </defs>

      {/* START */}
      <g>
        <circle cx={X0 - 30} cy={Y} r={16} fill="var(--color-surface-3)" stroke={running || current ? 'var(--color-accent)' : 'var(--color-line-2)'} strokeWidth={1.5} />
        <text x={X0 - 30} y={Y + 4} textAnchor="middle" fontSize={9} fontWeight={700} fill="var(--color-fg-2)">
          START
        </text>
        <line x1={X0 - 14} y1={Y} x2={xOf(0) - NODE_W / 2 - 2} y2={Y} stroke={running || current ? STROKE.active : STROKE.idle} strokeWidth={1.5} markerEnd={'url(#sg-arrow-' + (running || current ? 'active' : 'idle') + ')'} />
        <text x={X0 - 30} y={Y + 34} textAnchor="middle" fontSize={9} fill="var(--color-muted)">
          signed request
        </text>
      </g>

      {STAGE_ORDER.map((stage, i) => {
        const tone = stageStatus(checks, stage);
        const x = xOf(i);
        const isActive = activeStage === stage || (running && nextStage === stage && tone === 'idle');
        const stroke = tone !== 'idle' ? STROKE[tone] : isActive ? STROKE.active : 'var(--color-line-2)';
        const items = checks.filter((c) => c.stage === stage);
        const total = checkIds.filter((id) => CHECK_META[id].stage === stage).length;
        return (
          <g key={stage}>
            <rect x={x - NODE_W / 2} y={Y - NODE_H / 2} width={NODE_W} height={NODE_H} rx={10} fill={tone === 'pass' ? 'var(--color-ok-bg)' : tone === 'fail' ? 'var(--color-bad-bg)' : tone === 'warn' ? 'var(--color-warn-bg)' : 'var(--color-surface-2)'} stroke={stroke} strokeWidth={tone !== 'idle' || isActive ? 2 : 1.25} className={isActive && tone === 'idle' ? 'animate-pulse-soft' : undefined} />
            <text x={x} y={Y - 3} textAnchor="middle" fontSize={11.5} fontWeight={600} fill="var(--color-fg)">
              {STAGE_LABEL[stage]}
            </text>
            <text x={x} y={Y + 12} textAnchor="middle" fontSize={9} fill={tone !== 'idle' ? stroke : 'var(--color-muted)'} className="mono">
              {items.length}/{total} {tone === 'idle' ? 'pending' : tone === 'pass' ? 'ok' : tone}
            </text>
            {/* per-check dots */}
            <g transform={'translate(' + (x - ((total - 1) * 9) / 2) + ',' + (Y + NODE_H / 2 + 12) + ')'}>
              {checkIds
                .filter((id) => CHECK_META[id].stage === stage)
                .map((id, j) => {
                  const c = items.find((k) => k.id === id);
                  const fill = c ? STROKE[c.status] : 'var(--color-line-2)';
                  return <circle key={id} cx={j * 9} cy={0} r={3} fill={fill}>
                    <title>{id + (c ? ' — ' + c.status : '')}</title>
                  </circle>;
                })}
            </g>
            {i < STAGE_ORDER.length - 1 && (
              <line x1={x + NODE_W / 2 + 2} y1={Y} x2={xOf(i + 1) - NODE_W / 2 - 2} y2={Y} stroke={tone !== 'idle' ? STROKE.active : STROKE.idle} strokeWidth={1.5} markerEnd={'url(#sg-arrow-' + (tone !== 'idle' ? 'active' : 'idle') + ')'} />
            )}
          </g>
        );
      })}

      {/* conditional edge -> ALLOW / DENY */}
      <path d={'M ' + (lastX + NODE_W / 2 + 2) + ' ' + Y + ' C ' + (lastX + NODE_W / 2 + 60) + ' ' + Y + ', ' + (endX - 70) + ' ' + (Y - 34) + ', ' + (endX - 34) + ' ' + (Y - 34)} fill="none" stroke={STROKE[allowTone]} strokeWidth={allowTone === 'idle' ? 1.25 : 2.5} markerEnd={'url(#sg-arrow-' + allowTone + ')'} strokeDasharray={allowTone === 'idle' ? '3 4' : undefined} />
      <path d={'M ' + (lastX + NODE_W / 2 + 2) + ' ' + Y + ' C ' + (lastX + NODE_W / 2 + 60) + ' ' + Y + ', ' + (endX - 70) + ' ' + (Y + 34) + ', ' + (endX - 34) + ' ' + (Y + 34)} fill="none" stroke={STROKE[denyTone]} strokeWidth={denyTone === 'idle' ? 1.25 : 2.5} markerEnd={'url(#sg-arrow-' + denyTone + ')'} strokeDasharray={denyTone === 'idle' ? '3 4' : undefined} />
      <text x={lastX + NODE_W / 2 + 40} y={Y - 18} fontSize={8.5} fill="var(--color-muted)">
        all critical pass
      </text>
      <text x={lastX + NODE_W / 2 + 40} y={Y + 26} fontSize={8.5} fill="var(--color-muted)">
        any critical fail
      </text>
      <g>
        <rect x={endX - 32} y={Y - 34 - 13} width={68} height={26} rx={13} fill={allowTone === 'pass' ? 'var(--color-ok-bg)' : 'var(--color-surface-3)'} stroke={allowTone === 'pass' ? STROKE.pass : 'var(--color-line-2)'} strokeWidth={allowTone === 'pass' ? 2 : 1.25} />
        <text x={endX + 2} y={Y - 34 + 4} textAnchor="middle" fontSize={10.5} fontWeight={700} fill={allowTone === 'pass' ? STROKE.pass : 'var(--color-muted)'}>
          ALLOW
        </text>
        <rect x={endX - 32} y={Y + 34 - 13} width={68} height={26} rx={13} fill={denyTone === 'fail' ? 'var(--color-bad-bg)' : 'var(--color-surface-3)'} stroke={denyTone === 'fail' ? STROKE.fail : 'var(--color-line-2)'} strokeWidth={denyTone === 'fail' ? 2 : 1.25} />
        <text x={endX + 2} y={Y + 34 + 4} textAnchor="middle" fontSize={10.5} fontWeight={700} fill={denyTone === 'fail' ? STROKE.fail : 'var(--color-muted)'}>
          DENY
        </text>
        <text x={endX + 2} y={Y + 70} textAnchor="middle" fontSize={9} fill="var(--color-muted)">
          END · signed receipt
        </text>
      </g>

      <text x={X0 - 46} y={170} fontSize={9.5} fill="var(--color-muted)">
        state = list of Check results · each node is a deterministic predicate over signed evidence · no model call in any node
      </text>
    </svg>
  );
}
