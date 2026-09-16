'use client';
import { useState } from 'react';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ArrowLeft, KeyRound, FileBadge, ScrollText, History as HistoryIcon, TriangleAlert, Receipt, Braces, Fingerprint } from 'lucide-react';
import { Badge, Button, Card, Did, StatusIcon, Money, fmtDate, cx } from '../ui';
import { JsonView } from '../JsonView';
import { useTrustGate } from '../store';
import { ClientOnly } from '../ClientOnly';
import type { AgentKey } from '@/lib/demo/world';
import { fingerprint } from '@/lib/crypto/hash';
import { resolveDidKey, verificationMethodId } from '@/lib/identity/did-key';
import { verifyCredentialProof, checkValidityWindow, checkCredentialStatus } from '@/lib/credentials/verify';
import { verifyGrantProof } from '@/lib/authority/grant';
import { verifyAttestation, verifyDecisionReceipt } from '@/lib/receipts/receipts';
import { signDocument, verifyDocument } from '@/lib/crypto/data-integrity';
import { resolvePublicKeyForVerificationMethod } from '@/lib/identity/did-key';
import { b64url } from '@/lib/crypto/encoding';
import { randomNonce } from '@/lib/crypto/ed25519';

export function TrustProfile({ slug }: { slug: string }) {
  return (
    <ClientOnly>
      <Profile slug={slug} />
    </ClientOnly>
  );
}

function Section({ icon: Icon, title, children, count }: { icon: React.ComponentType<{ className?: string }>; title: string; children: React.ReactNode; count?: number }) {
  return (
    <Card
      title={
        <span className="inline-flex items-center gap-2">
          <Icon className="size-3.5" /> {title}
          {count !== undefined && <span className="text-muted normal-case tracking-normal">({count})</span>}
        </span>
      }
    >
      {children}
    </Card>
  );
}

function Profile({ slug }: { slug: string }) {
  const world = useTrustGate((s) => s.world);
  const version = useTrustGate((s) => s.version);
  const policy = useTrustGate((s) => s.policy);
  void version;
  const agent = world.agents[slug as AgentKey];
  const [json, setJson] = useState<Record<string, boolean>>({});
  const [challenge, setChallenge] = useState<{ nonce: string; proofValue: string; verified: boolean } | null>(null);
  if (!agent) notFound();

  const name = (did: string) => world.verifier.labels[did] ?? did;
  const claimed = agent.claimsDid ?? agent.did;
  const didDoc = resolveDidKey(claimed)?.document;
  const now = new Date();

  const runChallenge = () => {
    // Prove control: sign a fresh nonce with the key the agent actually holds, under the DID it claims.
    const nonce = b64url.encode(randomNonce(16));
    const signed = signDocument({ challenge: nonce, subject: claimed }, agent.keys.secretKey, {
      verificationMethod: verificationMethodId(claimed),
      proofPurpose: 'authentication',
      created: now.toISOString(),
    });
    setChallenge({ nonce, proofValue: signed.proof.proofValue, verified: verifyDocument(signed, resolvePublicKeyForVerificationMethod).valid });
  };

  return (
    <div className="space-y-5">
      <div>
        <Link href="/agents" className="inline-flex items-center gap-1 text-xs text-muted hover:text-fg">
          <ArrowLeft className="size-3" /> Agent directory
        </Link>
        <div className="mt-2 flex flex-wrap items-end gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">{agent.name}</h1>
          <Badge tone={agent.kind === 'buyer' ? 'ok' : agent.kind === 'clone' ? 'bad' : agent.kind === 'rogue' ? 'warn' : 'accent'}>{agent.kind === 'verifier' ? 'verifier' : agent.kind}</Badge>
          <span className="text-sm text-muted">{agent.org}</span>
        </div>
        <p className="mt-1 text-sm text-fg-2 max-w-3xl">{agent.description}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Section icon={KeyRound} title="Identity">
          <dl className="space-y-2 text-[13px]">
            <div className="flex gap-3">
              <dt className="w-32 text-muted shrink-0">{agent.claimsDid ? 'Claimed DID' : 'DID'}</dt>
              <dd className="min-w-0 break-all mono text-fg-2">{claimed}</dd>
            </div>
            {agent.claimsDid && (
              <div className="flex gap-3">
                <dt className="w-32 text-muted shrink-0">Actual DID</dt>
                <dd className="min-w-0 break-all mono text-bad">{agent.did}</dd>
              </div>
            )}
            <div className="flex gap-3">
              <dt className="w-32 text-muted shrink-0">Key fingerprint</dt>
              <dd className={cx('mono', agent.claimsDid ? 'text-bad' : 'text-fg-2')}>
                {fingerprint(agent.keys.publicKey)}
                {agent.claimsDid && <span className="ml-2 text-[11px]">(claimed DID’s key: {fingerprint(resolveDidKey(claimed)!.publicKey)})</span>}
              </dd>
            </div>
            <div className="flex gap-3">
              <dt className="w-32 text-muted shrink-0">Verification method</dt>
              <dd className="min-w-0 break-all mono text-fg-2 text-[12px]">{verificationMethodId(claimed)}</dd>
            </div>
            {agent.controller && (
              <div className="flex gap-3">
                <dt className="w-32 text-muted shrink-0">Controller</dt>
                <dd className="flex items-center gap-2">
                  {name(agent.controller)} <Did did={agent.controller} />
                </dd>
              </div>
            )}
          </dl>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <Button size="sm" variant="subtle" onClick={runChallenge}>
              <Fingerprint className="size-3.5" /> Challenge: prove control of {agent.claimsDid ? 'claimed' : 'this'} DID
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setJson((j) => ({ ...j, did: !j.did }))}>
              <Braces className="size-3.5" /> DID document
            </Button>
          </div>
          {challenge && (
            <div className={cx('mt-3 rounded-lg border p-3 text-[12px] animate-fade-up', challenge.verified ? 'border-ok/40 bg-ok-bg/50' : 'border-bad/40 bg-bad-bg/50')}>
              <div className="flex items-center gap-2 font-medium">
                <StatusIcon status={challenge.verified ? 'pass' : 'fail'} />
                {challenge.verified ? 'Signature over fresh nonce verifies under the DID’s key — control proven.' : 'Signature does NOT verify under the claimed DID’s key — this agent cannot prove control.'}
              </div>
              <div className="mt-1 mono text-muted break-all">nonce {challenge.nonce} · proof {challenge.proofValue.slice(0, 32)}…</div>
            </div>
          )}
          {json.did && didDoc && <JsonView value={didDoc} className="mt-3" title="DID Document" maxHeight="max-h-72" />}
        </Section>

        <Section icon={FileBadge} title="Credentials" count={agent.credentials.length}>
          {agent.credentials.length === 0 && <p className="text-sm text-muted">This agent holds no credentials{agent.kind === 'verifier' ? ' — it is the verifier in this demo.' : '.'}</p>}
          <div className="space-y-4">
            {agent.credentials.map((vc) => {
              const proof = verifyCredentialProof(vc);
              const window = checkValidityWindow(vc, now);
              const status = checkCredentialStatus(vc, world.verifier.resolveStatusList);
              const trusted = policy.require.trustedIssuers.includes(vc.issuer);
              const subjectMatches = vc.credentialSubject.id === agent.did;
              return (
                <div key={vc.id} className="rounded-lg border border-line bg-surface-2 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-[13.5px]">{vc.type.filter((t) => t !== 'VerifiableCredential').join(' / ')}</span>
                    <span className="text-xs text-muted">issued by</span>
                    <span className="text-xs">{name(vc.issuer)}</span>
                    <Did did={vc.issuer} />
                  </div>
                  <ul className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-1 text-[12px]">
                    <li className="flex items-center gap-2"><StatusIcon status={proof.valid ? 'pass' : 'fail'} size="size-3.5" /> issuer signature {proof.valid ? 'verifies' : 'INVALID'} (eddsa-jcs-2022)</li>
                    <li className="flex items-center gap-2"><StatusIcon status={trusted ? 'pass' : 'warn'} size="size-3.5" /> issuer {trusted ? 'trusted' : 'not trusted'} by verifier policy</li>
                    <li className="flex items-center gap-2"><StatusIcon status={window.active ? 'pass' : 'fail'} size="size-3.5" /> valid {vc.validFrom.slice(0, 10)} → {vc.validUntil?.slice(0, 10) ?? '∞'}</li>
                    <li className="flex items-center gap-2"><StatusIcon status={status.ok ? 'pass' : 'fail'} size="size-3.5" /> {status.revoked ? 'REVOKED' : status.ok ? 'not revoked' : 'status unknown'} · list index {vc.credentialStatus?.statusListIndex}</li>
                    <li className="flex items-center gap-2"><StatusIcon status={subjectMatches ? 'pass' : 'fail'} size="size-3.5" /> subject {subjectMatches ? 'is this agent' : 'is NOT this agent (copied credential)'}</li>
                  </ul>
                  <dl className="mt-2 grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-1 text-[12px]">
                    {Object.entries(vc.credentialSubject)
                      .filter(([k]) => k !== 'id')
                      .map(([k, v]) => (
                        <div key={k} className="min-w-0">
                          <dt className="text-muted">{k}</dt>
                          <dd className="truncate text-fg-2 mono" title={String(v)}>
                            {k === 'controller' ? name(String(v)) : String(v)}
                          </dd>
                        </div>
                      ))}
                  </dl>
                  <div className="mt-2 flex items-center gap-2">
                    <span className="mono text-[10.5px] text-muted truncate">{vc.id}</span>
                    <Button size="sm" variant="ghost" className="ml-auto" onClick={() => setJson((j) => ({ ...j, [vc.id]: !j[vc.id] }))}>
                      <Braces className="size-3.5" /> JSON
                    </Button>
                  </div>
                  {json[vc.id] && <JsonView value={vc} className="mt-2" title="VerifiableCredential" maxHeight="max-h-80" />}
                </div>
              );
            })}
          </div>
        </Section>

        <Section icon={ScrollText} title="Delegated authority" count={agent.grants.length}>
          {agent.grants.length === 0 && <p className="text-sm text-muted">No principal has delegated authority to this agent. A verified identity with no grant can do nothing.</p>}
          <div className="space-y-3">
            {agent.grants.map((g) => {
              const proof = verifyGrantProof(g);
              const window = checkValidityWindow(g, now);
              const d = g.authorizationDetails[0];
              const bound = agent.credentials[0]?.credentialSubject.controller === g.principal;
              return (
                <div key={g.id} className="rounded-lg border border-line bg-surface-2 p-3">
                  <div className="flex flex-wrap items-center gap-2 text-[13px]">
                    <span className="font-medium">{d.actions.join(', ')}</span>
                    <span className="text-muted">on</span>
                    <span className="mono">{d.locations.join(', ')}</span>
                    {d.constraints?.maxAmount && (
                      <>
                        <span className="text-muted">up to</span>
                        <span className="font-medium">
                          <Money value={d.constraints.maxAmount.value} />
                        </span>
                      </>
                    )}
                  </div>
                  <div className="mt-1 text-xs text-muted flex flex-wrap items-center gap-x-2">
                    <span>from principal</span> <span className="text-fg-2">{name(g.principal)}</span> <Did did={g.principal} /> <span>· {g.validFrom.slice(0, 10)} → {g.validUntil.slice(0, 10)}</span>
                  </div>
                  <ul className="mt-2 grid grid-cols-1 sm:grid-cols-3 gap-1 text-[12px]">
                    <li className="flex items-center gap-2"><StatusIcon status={proof.valid ? 'pass' : 'fail'} size="size-3.5" /> principal signature {proof.valid ? 'verifies' : 'INVALID'}</li>
                    <li className="flex items-center gap-2"><StatusIcon status={window.active ? 'pass' : 'fail'} size="size-3.5" /> {window.active ? 'within validity window' : window.expired ? 'EXPIRED' : 'not yet valid'}</li>
                    <li className="flex items-center gap-2"><StatusIcon status={bound ? 'pass' : 'warn'} size="size-3.5" /> principal {bound ? 'is' : 'is not'} attested controller</li>
                  </ul>
                  <div className="mt-2 flex items-center gap-2">
                    <span className="mono text-[10.5px] text-muted truncate">{g.id}</span>
                    <Button size="sm" variant="ghost" className="ml-auto" onClick={() => setJson((j) => ({ ...j, [g.id]: !j[g.id] }))}>
                      <Braces className="size-3.5" /> JSON
                    </Button>
                  </div>
                  {json[g.id] && <JsonView value={g} className="mt-2" title="CapabilityGrant" maxHeight="max-h-80" />}
                </div>
              );
            })}
          </div>
        </Section>

        <Section icon={HistoryIcon} title="Behavioral evidence" count={agent.attestations.length}>
          <p className="text-[12px] text-muted mb-3">Signed statements by counterparties. Each is verified individually and counted. This is what “reputation” means here — attributable evidence, never a number.</p>
          {agent.attestations.length === 0 && <p className="text-sm text-muted">No counterparty has attested to any interaction with this agent yet.</p>}
          <ul className="space-y-2">
            {agent.attestations.map((a) => {
              const v = verifyAttestation(a);
              return (
                <li key={a.id} className="rounded-lg border border-line bg-surface-2 p-3 text-[12.5px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusIcon status={v.valid ? 'pass' : 'fail'} size="size-3.5" />
                    <span className="font-medium">{name(a.issuer)}</span>
                    <span className="text-muted">attests</span>
                    <Badge tone={a.outcome === 'completed' ? 'ok' : 'warn'}>{a.outcome}</Badge>
                    <span className="text-muted">{a.action}</span>
                    {a.amount && <span className="font-medium"><Money value={a.amount.value} /></span>}
                    <span className="ml-auto text-[11px] text-muted mono">{fmtDate(a.observedAt)}</span>
                  </div>
                  <p className="mt-1 text-fg-2">{a.statement}</p>
                  {a.requestHash && <div className="mt-1 mono text-[10.5px] text-muted truncate">bound to request {a.requestHash}</div>}
                </li>
              );
            })}
          </ul>
        </Section>
      </div>

      <Section icon={Receipt} title="Decision receipts" count={agent.history.length}>
        {agent.history.length === 0 && <p className="text-sm text-muted">No decisions recorded yet for this agent in this session. Send a request from the Console.</p>}
        <ul className="divide-y divide-line">
          {agent.history.map((r) => {
            const v = verifyDecisionReceipt(r);
            return (
              <li key={r.id} className="py-2 flex flex-wrap items-center gap-3 text-[12.5px]">
                <Badge tone={r.decision === 'ALLOW' ? 'ok' : 'bad'}>{r.decision}</Badge>
                <span className="text-fg-2">{r.action} {r.resource}{r.amount ? <> · <Money value={r.amount.value} /></> : null}</span>
                <span className="text-muted">by {name(r.verifier)}</span>
                <span className="mono text-[11px] text-muted">{fmtDate(r.issuedAt)}</span>
                <span className="ml-auto inline-flex items-center gap-1 text-[11px]">
                  <StatusIcon status={v.valid ? 'pass' : 'fail'} size="size-3.5" /> receipt signature {v.valid ? 'verified' : 'invalid'}
                </span>
              </li>
            );
          })}
        </ul>
      </Section>

      {agent.riskFlags.length > 0 && (
        <Section icon={TriangleAlert} title="Risk flags">
          <ul className="space-y-1.5">
            {agent.riskFlags.map((f) => (
              <li key={f} className="flex items-start gap-2 text-[13px] text-warn">
                <TriangleAlert className="size-4 shrink-0 mt-0.5" /> {f}
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
