'use client';
import { useState } from 'react';
import { ShieldCheck, ShieldX, Loader2, Braces, ChevronDown, ChevronUp, Receipt, ArrowRight, RotateCcw } from 'lucide-react';
import { Badge, Button, CopyButton, Did, Money, cx, fmtTime } from '../ui';
import { useTrustGate } from '../store';
import { verifyDecisionReceipt } from '@/lib/receipts/receipts';
import { TOTAL_CHECKS } from '@/lib/policy/engine';
import { CHECK_META } from '@/lib/policy/checks';

export function DecisionCard() {
  const world = useTrustGate((s) => s.world);
  const running = useTrustGate((s) => s.running);
  const live = useTrustGate((s) => s.liveChecks);
  const current = useTrustGate((s) => s.current);
  const { openDrawer, rerunLast } = useTrustGate();
  const [why, setWhy] = useState(false);

  const liveFailed = live.filter((c) => c.status === 'fail' && c.critical).length;
  const provisional = running ? (liveFailed > 0 ? 'DENY' : 'PENDING') : current?.decision.decision ?? 'IDLE';
  const d = current?.decision;
  const receiptOk = d?.receipt ? verifyDecisionReceipt(d.receipt).valid : false;
  const name = (did: string) => world.verifier.labels[did] ?? did;

  const tone = provisional === 'ALLOW' ? 'ok' : provisional === 'DENY' ? 'bad' : provisional === 'PENDING' ? 'warn' : 'neutral';
  const border = { ok: 'border-ok/50 shadow-[0_0_0_1px_rgba(49,192,118,0.25),0_0_60px_-20px_rgba(49,192,118,0.5)]', bad: 'border-bad/50 shadow-[0_0_0_1px_rgba(240,78,92,0.25),0_0_60px_-20px_rgba(240,78,92,0.5)]', warn: 'border-warn/40', neutral: 'border-line' }[tone];

  return (
    <section className={cx('card overflow-hidden transition-all duration-300', border)}>
      <div className="p-5">
        <div className="flex items-start gap-5">
          <div className="min-w-0 flex-1">
            <div className="text-[11px] uppercase tracking-wide text-muted mb-1">Decision</div>
            <div key={provisional + (current?.id ?? '')} className={cx('flex items-center gap-3', provisional !== 'IDLE' && provisional !== 'PENDING' && 'animate-stamp')}>
              {provisional === 'ALLOW' && <ShieldCheck className="size-10 text-ok" />}
              {provisional === 'DENY' && <ShieldX className="size-10 text-bad" />}
              {provisional === 'PENDING' && <Loader2 className="size-10 text-warn animate-spin" />}
              <span
                className={cx(
                  'text-5xl font-semibold tracking-tight leading-none',
                  provisional === 'ALLOW' && 'text-ok',
                  provisional === 'DENY' && 'text-bad',
                  provisional === 'PENDING' && 'text-warn',
                  provisional === 'IDLE' && 'text-muted',
                )}
              >
                {provisional === 'PENDING' ? 'VERIFYING' : provisional === 'IDLE' ? '—' : provisional}
              </span>
            </div>
            {running && (
              <div className="mt-3 text-xs text-muted mono">
                {live.length}/{TOTAL_CHECKS} predicates evaluated{liveFailed ? ' · ' + liveFailed + ' failed' : ''}
              </div>
            )}
            {!running && !current && (
              <p className="mt-3 text-sm text-muted max-w-prose">
                Send a request from the console or fire an attack from the lab. The decision is the conjunction of {TOTAL_CHECKS} verifiable predicates — never a score.
              </p>
            )}
            {!running && d && current && (
              <>
                <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
                  <span className="font-medium">{name(d.subject)}</span>
                  <ArrowRight className="size-3.5 text-muted" />
                  <span className="font-medium">{name(d.verifier)}</span>
                  <span className="text-muted">·</span>
                  <span className="text-fg-2">
                    {d.action} <span className="mono text-xs">{d.resource}</span>
                  </span>
                  {d.amount && (
                    <>
                      <span className="text-muted">·</span>
                      <span className="text-fg font-medium">
                        <Money value={d.amount.value} />
                      </span>
                    </>
                  )}
                  {current.scenarioId && <Badge tone="accent">lab: {current.scenarioId}</Badge>}
                </div>
                <p className="mt-3 text-[14.5px] leading-relaxed text-fg">{d.explanation}</p>
                {current.note && <p className="mt-2 text-xs text-warn/90">{current.note}</p>}
                {current.priorSteps.length > 0 && (
                  <div className="mt-2 text-xs text-muted">
                    {current.priorSteps.map((s, i) => (
                      <div key={i}>
                        {s.label}: <span className={s.decision.allow ? 'text-ok' : 'text-bad'}>{s.decision.decision}</span> · nonce <span className="mono">{s.request.nonce}</span>
                      </div>
                    ))}
                  </div>
                )}
                {d.failedChecks.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {d.failedChecks
                      .filter((c) => c.id !== 'POLICY_SATISFIED')
                      .map((c) => (
                        <Badge key={c.id} tone="bad" mono tip={CHECK_META[c.id].help}>
                          ✕ {c.id}
                        </Badge>
                      ))}
                  </div>
                )}
              </>
            )}
          </div>
          {!running && d && (
            <div className="shrink-0 hidden sm:flex flex-col items-end gap-2 text-right">
              <div className="text-[11px] text-muted">
                {fmtTime(d.timestamp)} · {d.durationMs} ms
              </div>
              <div className="text-[11px] text-muted mono">
                {d.checks.filter((c) => c.status === 'pass').length} pass · {d.failedChecks.length} fail · {d.checks.filter((c) => c.status === 'skip').length} skip
              </div>
              <Badge tone="neutral" mono>
                {d.policyId}
              </Badge>
            </div>
          )}
        </div>

        {!running && d && (
          <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line pt-4">
            <Button variant="subtle" size="sm" onClick={() => setWhy((v) => !v)}>
              {why ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
              Why?
            </Button>
            <Button variant="subtle" size="sm" onClick={() => openDrawer('decision')}>
              <Braces className="size-3.5" /> Raw JSON
            </Button>
            <Button variant="subtle" size="sm" onClick={() => openDrawer('receipt')}>
              <Receipt className="size-3.5" /> Receipt
            </Button>
            <Button variant="ghost" size="sm" onClick={() => void rerunLast()} title="Send a fresh request with the same parameters">
              <RotateCcw className="size-3.5" /> Re-run
            </Button>
            {d.receipt && (
              <span className="ml-auto inline-flex items-center gap-2 text-[11px]">
                <Badge tone={receiptOk ? 'ok' : 'bad'}>{receiptOk ? '✓ receipt signature verified' : 'receipt signature INVALID'}</Badge>
                <span className="text-muted">signed by</span>
                <Did did={d.receipt.verifier} />
                <span className="text-muted mono hidden lg:inline" title={d.requestHash}>
                  req {d.requestHash.slice(7, 19)}…
                </span>
                <CopyButton text={d.requestHash} label="" />
              </span>
            )}
          </div>
        )}

        {why && !running && d && (
          <div className="mt-3 rounded-lg border border-line bg-surface-2 p-3 text-[12.5px] space-y-2 animate-fade-up">
            {d.failedChecks.length === 0 ? (
              <p className="text-fg-2">
                Every required predicate passed. The verifier’s policy <span className="mono">{d.policyId}</span> (hash <span className="mono">{d.policyHash.slice(7, 19)}…</span>) was satisfied by evidence presented by {name(d.subject)}.
              </p>
            ) : (
              d.failedChecks.map((c) => (
                <div key={c.id} className="flex gap-2">
                  <span className="mono text-bad shrink-0">{c.id}</span>
                  <span className="text-fg-2">{c.detail}</span>
                </div>
              ))
            )}
            <p className="text-muted">
              Evidence examined: {d.evidence.credentialIds.length} credential(s), {d.evidence.grantIds.length} grant(s), {d.evidence.attestationIds.length} attestation(s), {d.evidence.statusListIds.length} status list(s). Issuers: {d.evidence.issuerDids.map(name).join(', ') || 'none'}.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
