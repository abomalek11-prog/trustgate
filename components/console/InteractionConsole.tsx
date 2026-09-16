'use client';
import { Send, ArrowRight, KeyRound, FileBadge, ScrollText, History as HistoryIcon, Loader2 } from 'lucide-react';
import { Badge, Button, Card, Did, Label, cx } from '../ui';
import { useTrustGate } from '../store';
import type { AgentKey } from '@/lib/demo/world';
import { fingerprint } from '@/lib/crypto/hash';

const REQUESTERS: AgentKey[] = ['buyer', 'clone', 'rogue'];
const QUICK_AMOUNTS = [250, 500, 2000];

export function InteractionConsole() {
  const world = useTrustGate((s) => s.world);
  const version = useTrustGate((s) => s.version);
  const requester = useTrustGate((s) => s.requester);
  const amount = useTrustGate((s) => s.amount);
  const resource = useTrustGate((s) => s.resource);
  const running = useTrustGate((s) => s.running);
  const policy = useTrustGate((s) => s.policy);
  const { setRequester, setAmount, setResource, sendRequest, buyerRevoked } = useTrustGate();
  void version;

  const agent = world.agents[requester];
  const counterparty = world.agents.procurement;
  const vc = agent.credentials[0];
  const grant = agent.grants[0];
  const issuerName = vc ? (Object.values(world.issuers).find((i) => i.did === vc.issuer)?.name ?? vc.issuer) : null;
  const issuerTrusted = vc ? policy.require.trustedIssuers.includes(vc.issuer) : false;
  const revoked = requester !== 'rogue' && buyerRevoked();
  const cap = grant?.authorizationDetails[0]?.constraints?.maxAmount?.value;

  return (
    <Card
      title="Interaction Console"
      subtitle="Agent A asks Agent B to act. B runs TrustGate before doing anything."
      actions={
        <Badge tone="neutral" mono>
          action: purchase
        </Badge>
      }
    >
      <div className="space-y-4">
        <div>
          <Label hint="The agent sending the request. It signs the envelope with whatever private key it actually holds.">Requester</Label>
          <div className="grid grid-cols-3 gap-2">
            {REQUESTERS.map((k) => {
              const a = world.agents[k];
              const active = requester === k;
              return (
                <button
                  key={k}
                  type="button"
                  onClick={() => setRequester(k)}
                  className={cx(
                    'text-left rounded-lg border p-2.5 transition-colors',
                    active ? 'border-accent/60 bg-accent-bg' : 'border-line-2 bg-surface-2 hover:bg-surface-3',
                  )}
                >
                  <div className="text-[13px] font-medium leading-tight">{a.name}</div>
                  <div className="text-[11px] text-muted mt-0.5">{a.org}</div>
                  <div className="mt-1.5">
                    {a.kind === 'buyer' && <Badge tone="ok">verified</Badge>}
                    {a.kind === 'clone' && <Badge tone="bad">clone</Badge>}
                    {a.kind === 'rogue' && <Badge tone="warn">untrusted issuer</Badge>}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs text-muted">
          <span className="text-fg-2 font-medium">{agent.name}</span>
          <ArrowRight className="size-3.5" />
          <span className="text-fg-2 font-medium">{counterparty.name}</span>
          <span className="text-muted">·</span>
          <Did did={counterparty.did} />
        </div>

        <div className="grid grid-cols-5 gap-3">
          <div className="col-span-2">
            <Label hint="Amount the requester is asking the counterparty to spend. Compared against the principal's delegated cap AND the verifier's own policy cap.">Amount (USD)</Label>
            <div className="flex items-stretch rounded-lg border border-line-2 bg-surface-2 focus-within:border-accent/60">
              <span className="px-2.5 grid place-items-center text-muted text-sm">$</span>
              <input
                type="number"
                min={1}
                value={amount || ''}
                onChange={(e) => setAmount(Number(e.target.value))}
                className="w-full bg-transparent py-2 pr-3 text-[15px] tabular-nums outline-none"
                aria-label="Amount in USD"
              />
            </div>
            <div className="flex gap-1.5 mt-1.5">
              {QUICK_AMOUNTS.map((q) => (
                <button
                  key={q}
                  type="button"
                  onClick={() => setAmount(q)}
                  className={cx('rounded-md border px-2 h-6 text-[11px] tabular-nums', amount === q ? 'border-accent/60 text-accent bg-accent-bg' : 'border-line-2 text-muted hover:text-fg')}
                >
                  ${q.toLocaleString('en-US')}
                </button>
              ))}
            </div>
          </div>
          <div className="col-span-3">
            <Label hint="The thing being bought. Must match a location pattern in the capability grant (e.g. vendor:*).">Resource</Label>
            <input
              value={resource}
              onChange={(e) => setResource(e.target.value)}
              className="w-full rounded-lg border border-line-2 bg-surface-2 px-3 py-2 text-sm mono outline-none focus:border-accent/60"
              aria-label="Resource"
            />
            <div className="text-[11px] text-muted mt-1.5">Try <button type="button" className="mono text-fg-2 hover:text-accent" onClick={() => setResource('payroll:transfer')}>payroll:transfer</button> to leave the grant’s scope.</div>
          </div>
        </div>

        <div className="rounded-lg border border-line bg-surface-2 p-3">
          <div className="text-[11px] uppercase tracking-wide text-muted mb-2">Evidence this requester will present</div>
          <ul className="space-y-1.5 text-[12.5px]">
            <li className="flex items-center gap-2">
              <KeyRound className="size-3.5 text-muted" />
              {agent.claimsDid ? (
                <span>
                  Claims <span className="mono text-fg-2">{agent.claimsDid.slice(0, 22)}…</span> but signs with key <span className="mono text-bad">{fingerprint(agent.keys.publicKey)}</span>
                </span>
              ) : (
                <span>
                  Signs with its own key <span className="mono text-fg-2">{fingerprint(agent.keys.publicKey)}</span> (matches its DID)
                </span>
              )}
            </li>
            <li className="flex items-center gap-2">
              <FileBadge className="size-3.5 text-muted" />
              {vc ? (
                <span className="flex flex-wrap items-center gap-1.5">
                  VerifiedBusinessAgent from {issuerName}
                  <Badge tone={issuerTrusted ? 'ok' : 'warn'}>{issuerTrusted ? 'trusted issuer' : 'not trusted by policy'}</Badge>
                  {revoked && <Badge tone="bad">revoked</Badge>}
                </span>
              ) : (
                <span className="text-muted">no credential</span>
              )}
            </li>
            <li className="flex items-center gap-2">
              <ScrollText className="size-3.5 text-muted" />
              {grant ? (
                <span>
                  Purchase authority up to <span className="text-fg-2 tabular-nums">${cap?.toLocaleString('en-US')}</span> on <span className="mono text-fg-2">{grant.authorizationDetails[0].locations.join(', ')}</span> until {grant.validUntil.slice(0, 10)}
                </span>
              ) : (
                <span className="text-muted">no capability grant</span>
              )}
            </li>
            <li className="flex items-center gap-2">
              <HistoryIcon className="size-3.5 text-muted" />
              <span>
                {agent.attestations.length} signed counterparty attestation{agent.attestations.length === 1 ? '' : 's'} · {agent.history.length} decision receipt{agent.history.length === 1 ? '' : 's'}
              </span>
            </li>
          </ul>
        </div>

        <Button size="lg" className="w-full" onClick={() => void sendRequest()} disabled={running || !amount}>
          {running ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
          {running ? 'Verifying…' : 'Request Action'}
        </Button>
      </div>
    </Card>
  );
}
