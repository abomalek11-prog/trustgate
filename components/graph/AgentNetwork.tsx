'use client';
import { useTrustGate } from '../store';
import { STROKE, edgePath, toneFor, worstStatus, type EdgeTone, type NodeBox } from './graph-utils';
import type { Check, CheckId } from '@/lib/policy/types';
import type { AgentKey } from '@/lib/demo/world';
import { fingerprint } from '@/lib/crypto/hash';
import { shortDid } from '@/lib/identity/did-key';

type NodeId = 'verdant' | 'shady' | 'acme' | 'rogueHoldings' | 'contoso' | 'buyer' | 'clone' | 'rogue' | 'procurement' | 'planner';

const W = 180;
const H = 66;
const POS: Record<NodeId, NodeBox> = {
  verdant: { x: 150, y: 70, w: W, h: H },
  shady: { x: 380, y: 70, w: W, h: H },
  acme: { x: 610, y: 70, w: W, h: H },
  rogueHoldings: { x: 840, y: 70, w: W, h: H },
  contoso: { x: 1070, y: 70, w: W, h: H },
  planner: { x: 150, y: 330, w: W, h: H },
  buyer: { x: 430, y: 330, w: W, h: H },
  clone: { x: 430, y: 500, w: W, h: H },
  rogue: { x: 700, y: 500, w: W, h: H },
  procurement: { x: 1000, y: 400, w: 200, h: 78 },
};

const REQUEST_CHECKS: CheckId[] = ['IDENTITY_RESOLVED', 'REQUEST_AUDIENCE_MATCH', 'REQUEST_SIGNATURE_VALID', 'REQUEST_FRESH', 'NONCE_UNSEEN'];
const CRED_CHECKS: CheckId[] = ['CREDENTIAL_PRESENT', 'CREDENTIAL_SIGNATURE_VALID', 'CREDENTIAL_VALIDITY_WINDOW', 'CREDENTIAL_ISSUER_TRUSTED', 'CREDENTIAL_NOT_REVOKED'];
const AUTH_CHECKS: CheckId[] = ['AUTHORITY_PRESENT', 'AUTHORITY_SIGNATURE_VALID', 'AUTHORITY_PRINCIPAL_BOUND', 'AUTHORITY_ACTION_MATCH', 'AUTHORITY_RESOURCE_MATCH', 'AUTHORITY_VALIDITY_WINDOW', 'AUTHORITY_AMOUNT_WITHIN_GRANT'];
const HIST_CHECKS: CheckId[] = ['HISTORY_ATTESTATIONS_VERIFIED'];

interface EdgeSpec {
  id: string;
  from: NodeId;
  to: NodeId;
  label: string;
  /** which requester(s) this edge is evidence for */
  evidenceFor?: AgentKey[];
  checks?: CheckId[];
  dashed?: boolean;
  bow?: number;
  kind: 'credential' | 'grant' | 'attestation' | 'copy' | 'intent' | 'request' | 'decision';
}

const STATIC_EDGES: EdgeSpec[] = [
  { id: 'vc-buyer', from: 'verdant', to: 'buyer', label: 'VC · VerifiedBusinessAgent', evidenceFor: ['buyer', 'clone'], checks: CRED_CHECKS, kind: 'credential' },
  { id: 'vc-rogue', from: 'shady', to: 'rogue', label: 'VC · issuer NOT trusted', evidenceFor: ['rogue'], checks: CRED_CHECKS, kind: 'credential', bow: -20 },
  { id: 'grant-buyer', from: 'acme', to: 'buyer', label: 'Grant · purchase ≤ $500', evidenceFor: ['buyer', 'clone'], checks: AUTH_CHECKS, kind: 'grant', bow: 10 },
  { id: 'grant-rogue', from: 'rogueHoldings', to: 'rogue', label: 'Grant · purchase ≤ $500', evidenceFor: ['rogue'], checks: AUTH_CHECKS, kind: 'grant' },
  { id: 'att-contoso', from: 'contoso', to: 'buyer', label: 'Attestation · $340 completed', evidenceFor: ['buyer', 'clone'], checks: HIST_CHECKS, kind: 'attestation', bow: 40 },
  { id: 'copy', from: 'buyer', to: 'clone', label: 'copies public docs (no key)', dashed: true, kind: 'copy' },
  { id: 'intent', from: 'planner', to: 'buyer', label: 'intent: “buy 25 credits”', dashed: true, kind: 'intent' },
];

function Node({ box, title, sub, tag, tone, dashed, pulse, mono }: { box: NodeBox; title: string; sub?: string; tag?: string; tone?: EdgeTone; dashed?: boolean; pulse?: boolean; mono?: string }) {
  const stroke = tone && tone !== 'idle' ? STROKE[tone] : 'var(--color-line-2)';
  return (
    <g transform={'translate(' + (box.x - box.w / 2) + ',' + (box.y - box.h / 2) + ')'}>
      <rect width={box.w} height={box.h} rx={12} fill="var(--color-surface-2)" stroke={stroke} strokeWidth={tone && tone !== 'idle' ? 2 : 1.25} strokeDasharray={dashed ? '5 4' : undefined} className={pulse ? 'animate-pulse-soft' : undefined} />
      <text x={12} y={22} fontSize={13} fontWeight={600} fill="var(--color-fg)">
        {title}
      </text>
      {sub && (
        <text x={12} y={39} fontSize={10.5} fill="var(--color-muted)">
          {sub}
        </text>
      )}
      {mono && (
        <text x={12} y={box.h - 11} fontSize={10} fill="var(--color-fg-2)" className="mono">
          {mono}
        </text>
      )}
      {tag && (
        <g transform={'translate(' + (box.w - 8) + ',10)'}>
          <text textAnchor="end" fontSize={9.5} fontWeight={600} fill={stroke} letterSpacing={0.5}>
            {tag.toUpperCase()}
          </text>
        </g>
      )}
    </g>
  );
}

function Edge({ a, b, label, tone, dashed, bow = 0, flowing }: { a: NodeBox; b: NodeBox; label: string; tone: EdgeTone; dashed?: boolean; bow?: number; flowing?: boolean }) {
  const { d, mid } = edgePath(a, b, bow);
  const stroke = STROKE[tone];
  const marker = 'url(#arrow-' + tone + ')';
  return (
    <g>
      <path d={d} fill="none" stroke={stroke} strokeWidth={tone === 'idle' ? 1.25 : 2} strokeDasharray={flowing ? '8 6' : dashed ? '4 4' : undefined} className={flowing ? 'edge-flow' : undefined} markerEnd={marker} opacity={tone === 'idle' ? 0.8 : 1} />
      <text x={mid.x} y={mid.y - 6} textAnchor="middle" fontSize={10} fill={tone === 'idle' ? 'var(--color-muted)' : stroke} style={{ paintOrder: 'stroke', stroke: 'var(--color-bg)', strokeWidth: 4, strokeLinejoin: 'round' }}>
        {label}
      </text>
    </g>
  );
}

export function AgentNetwork() {
  const world = useTrustGate((s) => s.world);
  const version = useTrustGate((s) => s.version);
  const requester = useTrustGate((s) => s.requester);
  const running = useTrustGate((s) => s.running);
  const live = useTrustGate((s) => s.liveChecks);
  const current = useTrustGate((s) => s.current);
  const amount = useTrustGate((s) => s.amount);
  void version;

  const checks: Check[] = running ? live : current?.decision.checks ?? [];
  const activeRequester: AgentKey = running || current ? (current && !running ? current.requester : requester) : requester;
  const decided = !running && current ? current.decision : null;
  const northwindAtts = (k: AgentKey) => world.agents[k].attestations.filter((a) => a.issuer === world.agents.procurement.did).length;

  const nodeTone = (k: NodeId): EdgeTone | undefined => {
    if (k === 'procurement') return running ? 'active' : decided ? (decided.allow ? 'pass' : 'fail') : undefined;
    if (k === activeRequester) return running ? 'active' : decided ? (decided.allow ? 'pass' : 'fail') : 'active';
    return undefined;
  };

  return (
    <svg viewBox="0 0 1200 600" className="w-full h-auto" role="img" aria-label="Agent network graph">
      <defs>
        {(Object.keys(STROKE) as EdgeTone[]).map((t) => (
          <marker key={t} id={'arrow-' + t} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" fill={STROKE[t]} />
          </marker>
        ))}
      </defs>

      {/* lanes */}
      <text x={20} y={30} fontSize={10.5} fill="var(--color-muted)" letterSpacing={1}>
        ISSUERS · PRINCIPALS · COUNTERPARTIES — sign claims about agents
      </text>
      <line x1={20} y1={150} x2={1180} y2={150} stroke="var(--color-line)" strokeDasharray="2 6" />
      <text x={20} y={210} fontSize={10.5} fill="var(--color-muted)" letterSpacing={1}>
        AGENTS — hold keys, present evidence, exchange signed messages
      </text>

      {/* static evidence edges */}
      {STATIC_EDGES.map((e) => {
        const relevant = e.evidenceFor?.includes(activeRequester) ?? false;
        const status = relevant && e.checks ? worstStatus(checks, e.checks) : undefined;
        const tone: EdgeTone = e.kind === 'copy' || e.kind === 'intent' ? 'idle' : toneFor(status, relevant && running);
        return <Edge key={e.id} a={POS[e.from]} b={POS[e.to]} label={e.label} tone={tone} dashed={e.dashed} bow={e.bow} flowing={relevant && running && !status} />;
      })}

      {/* past attestations from the verifier to each agent (grow on ALLOW) */}
      {(['buyer', 'rogue'] as AgentKey[]).map((k) => {
        const n = northwindAtts(k);
        if (!n) return null;
        const relevant = activeRequester === k || (activeRequester === 'clone' && k === 'buyer');
        const status = relevant ? worstStatus(checks, HIST_CHECKS) : undefined;
        return <Edge key={'att-nw-' + k} a={POS.procurement} b={POS[k]} label={'Attestations · ' + n + ' from Procurement'} tone={toneFor(status, false)} bow={k === 'buyer' ? -70 : 40} />;
      })}

      {/* the live request edge and the decision edge */}
      {(() => {
        const from = POS[activeRequester];
        const reqStatus = worstStatus(checks, REQUEST_CHECKS);
        const reqTone = toneFor(reqStatus, running);
        const label = activeRequester === 'clone' ? 'ActionRequest · claims Buyer’s DID, signed with own key' : 'ActionRequest · signed · nonce · $' + (current && !running ? current.amount : amount).toLocaleString('en-US');
        return (
          <g>
            <Edge a={from} b={POS.procurement} label={label} tone={reqTone} bow={activeRequester === 'buyer' ? 30 : activeRequester === 'rogue' ? 20 : 60} flowing={running && !reqStatus} />
            {decided && <Edge a={POS.procurement} b={from} label={'Decision · ' + decided.decision + ' · signed receipt'} tone={decided.allow ? 'pass' : 'fail'} bow={activeRequester === 'buyer' ? 30 : activeRequester === 'rogue' ? 20 : 60} flowing />}
          </g>
        );
      })()}

      {/* nodes */}
      <Node box={POS.verdant} title={world.issuers.verdant.name} sub="issuer · trusted" mono={shortDid(world.issuers.verdant.did)} tag="issuer" />
      <Node box={POS.shady} title={world.issuers.shady.name} sub="issuer · NOT trusted by policy" mono={shortDid(world.issuers.shady.did)} tag="issuer" />
      <Node box={POS.acme} title={world.principals.acme.name} sub="principal · delegates authority" mono={shortDid(world.principals.acme.did)} tag="principal" />
      <Node box={POS.rogueHoldings} title={world.principals.rogueHoldings.name} sub="principal" mono={shortDid(world.principals.rogueHoldings.did)} tag="principal" />
      <Node box={POS.contoso} title={world.counterparties.contoso.name} sub="past counterparty" mono={shortDid(world.counterparties.contoso.did)} tag="attester" />

      <Node box={POS.planner} title="Planner / LLM brain" sub="proposes actions · NOT in the decision path" tag="pluggable" dashed mono="prompt injection ≠ authority" />
      <Node box={POS.buyer} title={world.agents.buyer.name} sub={'key ' + fingerprint(world.agents.buyer.keys.publicKey) + ' · ' + world.agents.buyer.attestations.length + ' attestations'} mono={shortDid(world.agents.buyer.did)} tag="verified" tone={nodeTone('buyer')} pulse={running && activeRequester === 'buyer'} />
      <Node box={POS.clone} title={world.agents.clone.name} sub={'own key ' + fingerprint(world.agents.clone.keys.publicKey) + ' ≠ Buyer’s'} mono={'claims ' + shortDid(world.agents.clone.claimsDid ?? '')} tag="attacker" tone={nodeTone('clone')} pulse={running && activeRequester === 'clone'} />
      <Node box={POS.rogue} title={world.agents.rogue.name} sub={'key ' + fingerprint(world.agents.rogue.keys.publicKey) + ' · 0 attestations'} mono={shortDid(world.agents.rogue.did)} tag="untrusted" tone={nodeTone('rogue')} pulse={running && activeRequester === 'rogue'} />
      <Node box={POS.procurement} title={world.agents.procurement.name} sub={running ? 'TrustGate · evaluating ' + live.length + '/20…' : decided ? 'TrustGate · ' + decided.decision + ' · ' + decided.durationMs + ' ms' : 'TrustGate · verifier · policy ' + world.verifier.policy.policyId} mono={shortDid(world.agents.procurement.did)} tag="verifier" tone={nodeTone('procurement')} pulse={running} />
    </svg>
  );
}
