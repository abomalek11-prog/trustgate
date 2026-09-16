'use client';
import Link from 'next/link';
import { Send, Loader2, ArrowRight, Brain, GitBranch, Lock } from 'lucide-react';
import { Badge, Button, Card, Money, cx } from '../ui';
import { ClientOnly } from '../ClientOnly';
import { useTrustGate } from '../store';
import { AgentNetwork } from './AgentNetwork';
import { VerifierStateGraph } from './VerifierStateGraph';
import { SCENARIOS, type ScenarioId } from '@/lib/demo/scenarios';
import type { AgentKey } from '@/lib/demo/world';

const REQUESTERS: AgentKey[] = ['buyer', 'clone', 'rogue'];

export function GraphPage() {
  return (
    <ClientOnly>
      <Inner />
    </ClientOnly>
  );
}

function Inner() {
  const world = useTrustGate((s) => s.world);
  const requester = useTrustGate((s) => s.requester);
  const amount = useTrustGate((s) => s.amount);
  const running = useTrustGate((s) => s.running);
  const current = useTrustGate((s) => s.current);
  const live = useTrustGate((s) => s.liveChecks);
  const { setRequester, setAmount, sendRequest, runScenario } = useTrustGate();
  const d = !running && current ? current.decision : null;

  return (
    <div className="space-y-5">
      <div className="flex flex-col lg:flex-row lg:items-end gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Agent Graph</h1>
          <p className="text-sm text-fg-2 mt-1 max-w-3xl">
            Who signs what for whom, what crosses the wire, and the verifier’s internal state machine. Run a request and watch the evidence edges light up as each predicate is evaluated.
          </p>
        </div>
        <div className="lg:ml-auto text-xs text-muted">
          Same engine and state as the <Link href="/" className="text-accent hover:underline">Console</Link> — decisions made here appear there too.
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        <div className="xl:col-span-9 space-y-5">
          <Card
            title="Agent network"
            subtitle="Nodes are did:key identities. Solid edges are signed documents; dashed edges are not evidence."
            actions={
              d && (
                <Badge tone={d.allow ? 'ok' : 'bad'}>
                  {d.decision} · {current?.requester} · <Money value={current?.amount ?? 0} />
                </Badge>
              )
            }
          >
            <AgentNetwork />
          </Card>

          <Card
            title="Verifier state machine (inside Procurement Agent)"
            subtitle="START → identity → signature → freshness → credential → issuer → revocation → authority → history → policy → ALLOW | DENY"
            actions={<span className="text-[11px] text-muted mono">{running ? live.length + '/20 evaluated' : d ? d.checks.filter((c) => c.status === 'pass').length + ' pass · ' + d.failedChecks.length + ' fail' : 'idle'}</span>}
          >
            <VerifierStateGraph />
            {d && <p className="mt-2 text-[13px] text-fg-2">{d.explanation}</p>}
          </Card>
        </div>

        <div className="xl:col-span-3 space-y-5">
          <Card title="Run" subtitle="Drive the graph.">
            <div className="space-y-3">
              <div className="grid grid-cols-1 gap-1.5">
                {REQUESTERS.map((k) => (
                  <button
                    key={k}
                    type="button"
                    onClick={() => setRequester(k)}
                    className={cx('text-left rounded-lg border px-3 py-2 text-[13px] transition-colors', requester === k ? 'border-accent/60 bg-accent-bg' : 'border-line-2 bg-surface-2 hover:bg-surface-3')}
                  >
                    {world.agents[k].name}
                    <span className="block text-[11px] text-muted">{world.agents[k].org}</span>
                  </button>
                ))}
              </div>
              <div className="flex gap-1.5">
                {[250, 500, 2000].map((q) => (
                  <button key={q} type="button" onClick={() => setAmount(q)} className={cx('flex-1 rounded-md border h-8 text-[12px] tabular-nums', amount === q ? 'border-accent/60 text-accent bg-accent-bg' : 'border-line-2 text-muted hover:text-fg')}>
                    ${q.toLocaleString('en-US')}
                  </button>
                ))}
              </div>
              <Button className="w-full" onClick={() => void sendRequest()} disabled={running}>
                {running ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
                {running ? 'Verifying…' : 'Request Action'}
              </Button>
              <div>
                <div className="text-[11px] uppercase tracking-wide text-muted mb-1.5">Attack Lab scenario</div>
                <select
                  className="w-full rounded-lg border border-line-2 bg-surface-2 px-2.5 py-2 text-[13px] outline-none focus:border-accent/60"
                  defaultValue=""
                  disabled={running}
                  onChange={(e) => {
                    const id = e.target.value as ScenarioId | '';
                    if (id) void runScenario(id);
                    e.currentTarget.value = '';
                  }}
                >
                  <option value="" disabled>
                    Run a scenario…
                  </option>
                  {SCENARIOS.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.title} → {s.expected}
                    </option>
                  ))}
                </select>
              </div>
              <Link href="/" className="inline-flex items-center gap-1 text-xs text-accent hover:underline">
                Full verification trace in the Console <ArrowRight className="size-3" />
              </Link>
            </div>
          </Card>

          <Card title="Where is the neural network?" subtitle="A deliberate design choice.">
            <ul className="space-y-3 text-[12.5px] text-fg-2">
              <li className="flex gap-2">
                <Lock className="size-4 shrink-0 text-ok mt-0.5" />
                <span>
                  <span className="text-fg font-medium">Nowhere in the decision path.</span> Every node in the verifier’s graph is a deterministic predicate over signed bytes — Ed25519 signatures, hashes, dates, policy fields. There is no model call, no embedding, no score.
                </span>
              </li>
              <li className="flex gap-2">
                <Brain className="size-4 shrink-0 text-accent mt-0.5" />
                <span>
                  <span className="text-fg font-medium">An LLM can be the agent’s planner</span> (dashed node): it decides <em>what</em> to ask for — “buy 25 credits”. It never touches the private key’s authority: whatever it proposes must still be signed by the agent and pass the gate.
                </span>
              </li>
              <li className="flex gap-2">
                <GitBranch className="size-4 shrink-0 text-warn mt-0.5" />
                <span>
                  <span className="text-fg font-medium">Why that matters:</span> a hallucinating or prompt-injected planner can propose a $2,000 purchase — the graph still ends in DENY, because authority comes from a principal’s signature, not from anything a model says.
                </span>
              </li>
            </ul>
            <p className="mt-3 text-[11px] text-muted">
              If you use LangGraph/AutoGen/CrewAI, TrustGate is the gate node you put between “decide” and “act”: <span className="mono">POST /api/gate</span> with the signed request; branch on <span className="mono">decision</span>.
            </p>
          </Card>
        </div>
      </div>
    </div>
  );
}
