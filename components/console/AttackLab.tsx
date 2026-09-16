'use client';
import { Skull, Fingerprint, FileBadge, ScrollText, Timer, Gavel, Undo2, Play } from 'lucide-react';
import { Badge, Button, Card, cx } from '../ui';
import { useTrustGate } from '../store';
import { SCENARIOS, type ScenarioCategory } from '@/lib/demo/scenarios';

const CAT_ICON: Record<ScenarioCategory, React.ComponentType<{ className?: string }>> = {
  identity: Fingerprint,
  credential: FileBadge,
  authority: ScrollText,
  freshness: Timer,
  policy: Gavel,
};

export function AttackLab() {
  const running = useTrustGate((s) => s.running);
  const current = useTrustGate((s) => s.current);
  const version = useTrustGate((s) => s.version);
  const { runScenario, setBuyerRevoked, buyerRevoked } = useTrustGate();
  void version;
  const revoked = buyerRevoked();

  return (
    <Card
      title="Attack Lab"
      subtitle="One click = a real attack executed against the real verifier. Nothing here is a mocked red screen."
      actions={<Skull className="size-4 text-muted" />}
    >
      {revoked && (
        <div className="mb-3 flex items-center justify-between gap-3 rounded-lg border border-bad/40 bg-bad-bg px-3 py-2 text-xs">
          <span>
            <span className="font-medium text-bad">Buyer Agent’s credential is currently REVOKED</span>
            <span className="text-fg-2"> — Verdant Registry’s signed status list has bit 42 set. Every Buyer request will be denied until restored.</span>
          </span>
          <Button size="sm" variant="outline" onClick={() => setBuyerRevoked(false)}>
            <Undo2 className="size-3.5" /> Restore credential
          </Button>
        </div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {SCENARIOS.map((s) => {
          const Icon = CAT_ICON[s.category];
          const isCurrent = current?.scenarioId === s.id;
          const outcome = isCurrent ? current?.decision.decision : undefined;
          return (
            <button
              key={s.id}
              type="button"
              disabled={running}
              onClick={() => void runScenario(s.id)}
              className={cx(
                'group text-left rounded-lg border p-3 transition-colors disabled:opacity-60',
                isCurrent ? (outcome === 'ALLOW' ? 'border-ok/50 bg-ok-bg/40' : 'border-bad/50 bg-bad-bg/40') : 'border-line-2 bg-surface-2 hover:bg-surface-3 hover:border-line-2',
              )}
            >
              <div className="flex items-center gap-2">
                <Icon className={cx('size-3.5', s.attack ? 'text-muted' : 'text-ok')} />
                <span className="text-[13px] font-medium">{s.title}</span>
                <span className="ml-auto inline-flex items-center gap-1.5">
                  {outcome ? (
                    <Badge tone={outcome === 'ALLOW' ? 'ok' : 'bad'}>{outcome}</Badge>
                  ) : (
                    <Badge tone={s.expected === 'ALLOW' ? 'ok' : 'neutral'} className="opacity-80">
                      expect {s.expected}
                    </Badge>
                  )}
                  <Play className="size-3 text-muted opacity-0 group-hover:opacity-100 transition-opacity" />
                </span>
              </div>
              <p className="mt-1 text-[11.5px] text-muted leading-snug">{s.description}</p>
              <p className="mt-1 text-[11px] text-fg-2 leading-snug">
                <span className="text-muted">Caught by: </span>
                {s.defense}
              </p>
            </button>
          );
        })}
      </div>
    </Card>
  );
}
