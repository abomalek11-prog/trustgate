'use client';
import { useState } from 'react';
import { Fingerprint, PenLine, Timer, FileBadge, Building2, Ban, ScrollText, History as HistoryIcon, Gavel, ChevronRight, Info } from 'lucide-react';
import { Badge, Card, StatusIcon, cx, toneForStatus } from '../ui';
import { useTrustGate } from '../store';
import { CHECK_META, STAGE_LABEL, STAGE_ORDER } from '@/lib/policy/checks';
import type { Check, Stage } from '@/lib/policy/types';

const STAGE_ICON: Record<Stage, React.ComponentType<{ className?: string }>> = {
  identity: Fingerprint,
  signature: PenLine,
  freshness: Timer,
  credential: FileBadge,
  issuer: Building2,
  revocation: Ban,
  authority: ScrollText,
  history: HistoryIcon,
  policy: Gavel,
};

const STAGE_BLURB: Record<Stage, string> = {
  identity: 'Who is asking? The DID must resolve to a key, and the request must be addressed to us.',
  signature: 'Can they prove it? Ed25519 signature over the canonical envelope.',
  freshness: 'Is this new? Timestamp window + one-time nonce.',
  credential: 'What do trusted issuers say about them? Signed VC, about this subject, in date.',
  issuer: 'Do WE trust that issuer? A verifier-local choice.',
  revocation: 'Is it still true? Issuer-signed status list.',
  authority: 'What did their principal actually delegate? Action, resource, amount, time.',
  history: 'What have counterparties signed about them? Evidence, not a score.',
  policy: 'Our own rules on top: caps, minimums, the final conjunction.',
};

export function VerificationTrace() {
  const running = useTrustGate((s) => s.running);
  const live = useTrustGate((s) => s.liveChecks);
  const current = useTrustGate((s) => s.current);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const checks: Check[] = running ? live : current?.decision.checks ?? [];
  const byStage = new Map<Stage, Check[]>();
  for (const c of checks) byStage.set(c.stage, [...(byStage.get(c.stage) ?? []), c]);
  const currentStage = running ? live[live.length - 1]?.stage : undefined;

  if (!running && !current) {
    return (
      <Card title="Verification Trace" subtitle="identity → signature → freshness → credential → issuer → revocation → authority → history → policy">
        <ol className="space-y-2">
          {STAGE_ORDER.map((s) => {
            const Icon = STAGE_ICON[s];
            return (
              <li key={s} className="flex items-center gap-3 text-sm text-muted">
                <span className="grid place-items-center size-7 rounded-md border border-line bg-surface-2">
                  <Icon className="size-3.5" />
                </span>
                <span className="w-24 text-fg-2">{STAGE_LABEL[s]}</span>
                <span className="text-xs">{STAGE_BLURB[s]}</span>
              </li>
            );
          })}
        </ol>
      </Card>
    );
  }

  return (
    <Card
      title="Verification Trace"
      subtitle="Every predicate is evaluated and shown — nothing short-circuits, so you can see exactly what held and what did not."
      actions={
        <span className="text-[11px] text-muted mono">
          {checks.length} checks{running && ' · running'}
        </span>
      }
    >
      <ol className="relative">
        <span className="absolute left-[13px] top-3 bottom-3 w-px bg-line" aria-hidden />
        {STAGE_ORDER.map((stage) => {
          const items = byStage.get(stage) ?? [];
          const reached = items.length > 0;
          const active = currentStage === stage;
          const stageStatus = items.some((c) => c.status === 'fail') ? 'fail' : items.some((c) => c.status === 'warn') ? 'warn' : items.length && items.every((c) => c.status === 'skip') ? 'skip' : reached ? 'pass' : 'pending';
          const Icon = STAGE_ICON[stage];
          return (
            <li key={stage} className={cx('relative pl-10 pb-4 last:pb-0', !reached && !running && 'opacity-40')}>
              <span
                className={cx(
                  'absolute left-0 top-0 grid place-items-center size-7 rounded-md border bg-surface-2 transition-colors',
                  stageStatus === 'fail' && 'border-bad/50 text-bad',
                  stageStatus === 'pass' && 'border-ok/50 text-ok',
                  stageStatus === 'warn' && 'border-warn/50 text-warn',
                  stageStatus === 'skip' && 'border-line-2 text-muted',
                  stageStatus === 'pending' && (active ? 'border-accent text-accent' : 'border-line text-muted'),
                )}
              >
                <Icon className="size-3.5" />
              </span>
              <div className="flex items-center gap-2 h-7">
                <span className="text-sm font-medium">{STAGE_LABEL[stage]}</span>
                <span className="text-[11px] text-muted hidden md:inline" data-tip={STAGE_BLURB[stage]}>
                  <Info className="size-3 inline -mt-0.5" />
                </span>
                {reached && (
                  <Badge tone={stageStatus === 'pending' ? 'neutral' : toneForStatus[stageStatus]} className="ml-auto">
                    {stageStatus === 'pass' ? 'verified' : stageStatus === 'fail' ? 'failed' : stageStatus === 'warn' ? 'warning' : 'skipped'}
                  </Badge>
                )}
                {!reached && active && <span className="ml-auto text-[11px] text-accent animate-pulse-soft">evaluating…</span>}
              </div>
              {items.length > 0 && (
                <ul className="mt-1 space-y-1">
                  {items.map((c) => {
                    const isOpen = open[c.id] ?? c.status === 'fail';
                    return (
                      <li key={c.id} className="animate-fade-up">
                        <button
                          type="button"
                          onClick={() => setOpen((o) => ({ ...o, [c.id]: !isOpen }))}
                          className={cx(
                            'w-full text-left rounded-md border px-2.5 py-1.5 transition-colors',
                            c.status === 'fail' ? 'border-bad/30 bg-bad-bg/60' : c.status === 'warn' ? 'border-warn/30 bg-warn-bg/50' : 'border-line bg-surface-2 hover:bg-surface-3',
                          )}
                        >
                          <div className="flex items-center gap-2">
                            <StatusIcon status={c.status} />
                            <span className="text-[13px]">{c.title}</span>
                            <span className="mono text-[10.5px] text-muted hidden lg:inline" data-tip={CHECK_META[c.id].help}>
                              {c.id}
                            </span>
                            {!c.critical && c.status !== 'pass' && (
                              <Badge tone="neutral" className="ml-1">
                                non-blocking
                              </Badge>
                            )}
                            <ChevronRight className={cx('size-3.5 text-muted ml-auto transition-transform', isOpen && 'rotate-90')} />
                          </div>
                          {isOpen && (
                            <div className="mt-1.5 pl-6 text-[12px] text-fg-2 leading-relaxed">
                              <div>{c.detail}</div>
                              <div className="mt-1 text-[11px] text-muted">{CHECK_META[c.id].help}</div>
                              {Object.keys(c.evidence).length > 0 && (
                                <div className="mt-1.5 flex flex-wrap gap-1">
                                  {Object.entries(c.evidence).map(([k, v]) => (
                                    <span key={k} className="mono text-[10.5px] rounded border border-line-2 bg-surface px-1.5 py-0.5 text-muted max-w-full truncate" title={k + ' = ' + v}>
                                      <span className="text-fg-2">{k}</span>={v.length > 44 ? v.slice(0, 22) + '…' + v.slice(-14) : v}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </li>
          );
        })}
      </ol>
    </Card>
  );
}
