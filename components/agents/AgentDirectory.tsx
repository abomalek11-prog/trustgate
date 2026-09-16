'use client';
import Link from 'next/link';
import { ArrowRight, KeyRound, FileBadge, ScrollText, History as HistoryIcon, TriangleAlert, Building2, Landmark, Store } from 'lucide-react';
import { Badge, Card, Did, cx } from '../ui';
import { useTrustGate } from '../store';
import { ClientOnly } from '../ClientOnly';
import { fingerprint } from '@/lib/crypto/hash';
import { isRevoked } from '@/lib/credentials/status-list';
import type { AgentActor } from '@/lib/demo/world';

const KIND_TONE = { buyer: 'ok', verifier: 'accent', clone: 'bad', rogue: 'warn' } as const;
const KIND_LABEL = { buyer: 'verified agent', verifier: 'verifier', clone: 'spoofing clone', rogue: 'untrusted' } as const;

export function AgentDirectory() {
  return (
    <ClientOnly>
      <Directory />
    </ClientOnly>
  );
}

function Directory() {
  const world = useTrustGate((s) => s.world);
  const version = useTrustGate((s) => s.version);
  const policy = useTrustGate((s) => s.policy);
  void version;
  const agents = Object.values(world.agents);
  const others = [
    { icon: Building2, title: 'Issuers', items: Object.values(world.issuers), blurb: 'Sign VerifiedBusinessAgent credentials and publish signed status lists.' },
    { icon: Landmark, title: 'Principals', items: Object.values(world.principals), blurb: 'Delegate scoped authority to agents via signed capability grants.' },
    { icon: Store, title: 'Counterparties', items: Object.values(world.counterparties), blurb: 'Sign attestations about past interactions.' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Agent Directory</h1>
        <p className="text-sm text-fg-2 mt-1 max-w-3xl">
          Every agent is a <span className="mono">did:key</span> — the identifier <em>is</em> the public key. What differs between them is the evidence they can present and whether they can actually sign for the identity they claim.
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {agents.map((a) => (
          <AgentCard key={a.did} agent={a} trustedIssuers={policy.require.trustedIssuers} revokedFn={(idx, issuerDid) => {
            const issuer = Object.values(world.issuers).find((i) => i.did === issuerDid);
            return issuer ? isRevoked(issuer.statusList, idx) : false;
          }} issuerName={(did) => world.verifier.labels[did] ?? did} />
        ))}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {others.map((g) => (
          <Card key={g.title} title={g.title} subtitle={g.blurb}>
            <ul className="space-y-3">
              {g.items.map((i) => (
                <li key={i.did} className="flex items-start gap-3">
                  <span className="grid place-items-center size-8 rounded-md border border-line bg-surface-2 shrink-0">
                    <g.icon className="size-4 text-muted" />
                  </span>
                  <div className="min-w-0">
                    <div className="text-sm font-medium">{i.name}</div>
                    <div className="text-[11px] text-muted">{i.description}</div>
                    <div className="mt-1 flex items-center gap-2">
                      <Did did={i.did} />
                      {'statusList' in i && (
                        <Badge tone={policy.require.trustedIssuers.includes(i.did) ? 'ok' : 'warn'}>{policy.require.trustedIssuers.includes(i.did) ? 'trusted by verifier' : 'not trusted'}</Badge>
                      )}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </Card>
        ))}
      </div>
    </div>
  );
}

function AgentCard({ agent: a, trustedIssuers, revokedFn, issuerName }: { agent: AgentActor; trustedIssuers: string[]; revokedFn: (idx: number, issuer: string) => boolean; issuerName: (did: string) => string }) {
  const slug = a.key.replace(/^agent:/, '');
  return (
    <Link href={'/agents/' + slug} className={cx('card block p-5 hover:border-line-2 transition-colors group', a.kind === 'clone' && 'border-bad/30')}>
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-semibold tracking-tight">{a.name}</h2>
            <Badge tone={KIND_TONE[a.kind]}>{KIND_LABEL[a.kind]}</Badge>
          </div>
          <div className="text-xs text-muted">{a.org} · {a.role}</div>
        </div>
        <ArrowRight className="size-4 text-muted group-hover:text-fg transition-colors" />
      </div>
      <p className="mt-2 text-[12.5px] text-fg-2">{a.description}</p>

      <div className="mt-3 space-y-1.5 text-[12.5px]">
        <div className="flex items-center gap-2">
          <KeyRound className="size-3.5 text-muted shrink-0" />
          {a.claimsDid ? (
            <span className="flex flex-wrap items-center gap-x-2">
              <span className="text-muted">claims</span>
              <Did did={a.claimsDid} />
              <span className="text-muted">actual key</span>
              <span className="mono text-bad">{fingerprint(a.keys.publicKey)}</span>
              <Badge tone="bad">mismatch</Badge>
            </span>
          ) : (
            <span className="flex flex-wrap items-center gap-x-2">
              <Did did={a.did} />
              <span className="mono text-muted">key {fingerprint(a.keys.publicKey)}</span>
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <FileBadge className="size-3.5 text-muted shrink-0" />
          {a.credentials.length === 0 && <span className="text-muted">no credentials{a.kind === 'verifier' ? ' (it verifies; it does not present)' : ''}</span>}
          {a.credentials.map((vc) => {
            const trusted = trustedIssuers.includes(vc.issuer);
            const revoked = vc.credentialStatus ? revokedFn(Number(vc.credentialStatus.statusListIndex), vc.issuer) : false;
            return (
              <span key={vc.id} className="inline-flex items-center gap-1.5">
                <Badge tone={revoked ? 'bad' : trusted ? 'ok' : 'warn'}>{vc.type.filter((t) => t !== 'VerifiableCredential').join('/')}</Badge>
                <span className="text-muted">by {issuerName(vc.issuer)}</span>
                {revoked && <Badge tone="bad">revoked</Badge>}
                {!trusted && !revoked && <Badge tone="warn">issuer untrusted</Badge>}
              </span>
            );
          })}
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <ScrollText className="size-3.5 text-muted shrink-0" />
          {a.grants.length === 0 && <span className="text-muted">no delegated authority</span>}
          {a.grants.map((g) => (
            <Badge key={g.id} tone="accent" mono>
              {g.authorizationDetails[0].actions.join('/')} ≤ ${g.authorizationDetails[0].constraints?.maxAmount?.value.toLocaleString('en-US')} · {g.authorizationDetails[0].locations.join(',')} · until {g.validUntil.slice(0, 10)}
            </Badge>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <HistoryIcon className="size-3.5 text-muted shrink-0" />
          <span className="text-fg-2">
            {a.attestations.length} signed attestation{a.attestations.length === 1 ? '' : 's'} · {a.history.length} decision receipt{a.history.length === 1 ? '' : 's'}
          </span>
          <span className="text-[11px] text-muted">(evidence, not a score)</span>
        </div>
        {a.riskFlags.map((f) => (
          <div key={f} className="flex items-start gap-2 text-[12px] text-warn">
            <TriangleAlert className="size-3.5 shrink-0 mt-0.5" />
            <span>{f}</span>
          </div>
        ))}
      </div>
    </Link>
  );
}
