'use client';
import { Card, Badge, Money, fmtTime } from '../ui';
import { useTrustGate } from '../store';

export function ActivityLog() {
  const log = useTrustGate((s) => s.log);
  const world = useTrustGate((s) => s.world);
  if (log.length === 0) return null;
  const name = (did: string) => world.verifier.labels[did] ?? did;
  return (
    <Card title="Activity" subtitle="Every decision — ALLOW or DENY — produced a verifier-signed receipt. ALLOWs also earned the requester a new counterparty attestation.">
      <ul className="divide-y divide-line text-[12.5px]">
        {log.slice(0, 12).map((r) => {
          const root = r.decision.failedChecks.find((c) => c.id !== 'POLICY_SATISFIED');
          return (
            <li key={r.id} className="py-2 flex items-center gap-3">
              <span className="mono text-[11px] text-muted w-16">{fmtTime(r.at)}</span>
              <Badge tone={r.decision.allow ? 'ok' : 'bad'} className="w-14 justify-center">
                {r.decision.decision}
              </Badge>
              <span className="text-fg-2 truncate">
                {name(r.decision.subject)} → {name(r.decision.verifier)} · <Money value={r.amount} />
              </span>
              {r.scenarioId && <Badge tone="accent">{r.scenarioId}</Badge>}
              <span className="ml-auto mono text-[11px] text-muted truncate max-w-[40%]">{root ? root.id : 'all ' + r.decision.checks.filter((c) => c.critical).length + ' required checks passed'}</span>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
