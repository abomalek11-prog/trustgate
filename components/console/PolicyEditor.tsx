'use client';
import { useMemo, useState } from 'react';
import { Gavel, RotateCcw, Braces, Check } from 'lucide-react';
import { Badge, Button, Card, Label, Toggle, cx } from '../ui';
import { useTrustGate } from '../store';
import type { Policy } from '@/lib/policy/types';
import { hashDocument } from '@/lib/crypto/hash';

export function PolicyEditor() {
  const world = useTrustGate((s) => s.world);
  const policy = useTrustGate((s) => s.policy);
  const current = useTrustGate((s) => s.current);
  const { setPolicy, resetPolicy } = useTrustGate();
  const [showJson, setShowJson] = useState(false);
  const [jsonError, setJsonError] = useState<string | null>(null);
  // The textarea draft is keyed to the policy it was edited from; when the
  // policy changes elsewhere (form field, reset) the draft resets automatically.
  const policyText = useMemo(() => JSON.stringify(policy, null, 2), [policy]);
  const [edit, setEdit] = useState<{ base: string; text: string } | null>(null);
  const draft = edit && edit.base === policyText ? edit.text : policyText;
  const setDraft = (text: string) => setEdit({ base: policyText, text });

  const req = policy.require;
  const update = (fn: (p: Policy) => void) => {
    const next = JSON.parse(JSON.stringify(policy)) as Policy;
    fn(next);
    next.version = policy.version + 1;
    setPolicy(next);
  };
  const issuers = Object.values(world.issuers);
  const capEnabled = req.authority.maxAmount !== null;

  return (
    <Card
      title="Policy Editor"
      subtitle={
        <>
          The verifier’s own rules. Change a field — the last interaction re-runs immediately.
          {current && <span className="text-accent"> Watching: {current.scenarioId ?? 'console request'}.</span>}
        </>
      }
      actions={
        <>
          <Badge tone="neutral" mono tip="SHA-256 over the canonical policy JSON. Every decision receipt records the hash of the exact policy that produced it.">
            {hashDocument(policy).slice(7, 17)}
          </Badge>
          <Button size="sm" variant="ghost" onClick={() => setShowJson((v) => !v)}>
            <Braces className="size-3.5" /> JSON
          </Button>
          <Button size="sm" variant="ghost" onClick={resetPolicy} title="Restore the default policy">
            <RotateCcw className="size-3.5" />
          </Button>
        </>
      }
    >
      <div className="flex items-center gap-2 mb-4 text-xs text-muted">
        <Gavel className="size-3.5" />
        <span className="mono text-fg-2">{policy.policyId}</span>
        <span>v{policy.version}</span>
        <span>· action: {policy.action}</span>
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-4">
        <div>
          <Label hint="The verifier's own spend cap, applied on top of whatever the principal delegated. Lower it below $250 and the legitimate purchase flips to DENY.">Verifier max amount (USD)</Label>
          <div className="flex items-center gap-2">
            <div className={cx('flex items-stretch rounded-lg border bg-surface-2 flex-1', capEnabled ? 'border-line-2 focus-within:border-accent/60' : 'border-line opacity-50')}>
              <span className="px-2.5 grid place-items-center text-muted text-sm">$</span>
              <input
                type="number"
                min={0}
                disabled={!capEnabled}
                value={req.authority.maxAmount?.value ?? ''}
                onChange={(e) => update((p) => (p.require.authority.maxAmount = { value: Number(e.target.value) || 0, currency: 'USD' }))}
                className="w-full bg-transparent py-1.5 pr-2 text-sm tabular-nums outline-none"
              />
            </div>
            <button
              type="button"
              className="text-[11px] text-muted hover:text-fg whitespace-nowrap"
              onClick={() => update((p) => (p.require.authority.maxAmount = capEnabled ? null : { value: 500, currency: 'USD' }))}
            >
              {capEnabled ? 'no cap' : 'set cap'}
            </button>
          </div>
        </div>
        <div>
          <Label hint="Requests older than this are stale. The nonce cache only needs to remember nonces for this long.">Request max age (s)</Label>
          <input
            type="number"
            min={1}
            value={req.requestMaxAgeSeconds}
            onChange={(e) => update((p) => (p.require.requestMaxAgeSeconds = Math.max(1, Number(e.target.value) || 1)))}
            className="w-full rounded-lg border border-line-2 bg-surface-2 px-3 py-1.5 text-sm tabular-nums outline-none focus:border-accent/60"
          />
        </div>

        <div className="col-span-2">
          <Label hint="Only credentials signed by these issuers count. Tick Shady Certs and the Rogue Reseller Bot becomes acceptable — trust in issuers is a local choice.">Trusted issuers</Label>
          <div className="flex flex-wrap gap-2">
            {issuers.map((i) => {
              const on = req.trustedIssuers.includes(i.did);
              return (
                <button
                  key={i.did}
                  type="button"
                  onClick={() => update((p) => (p.require.trustedIssuers = on ? p.require.trustedIssuers.filter((d) => d !== i.did) : [...p.require.trustedIssuers, i.did]))}
                  className={cx('inline-flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-sm transition-colors', on ? 'border-ok/50 bg-ok-bg text-fg' : 'border-line-2 bg-surface-2 text-muted hover:text-fg')}
                >
                  <span className={cx('grid place-items-center size-4 rounded border', on ? 'border-ok bg-ok text-bg' : 'border-line-2')}>{on && <Check className="size-3" />}</span>
                  {i.name}
                  <span className="mono text-[10px] text-muted">{i.did.slice(8, 16)}…</span>
                </button>
              );
            })}
          </div>
        </div>

        <div>
          <Label hint="Credential types the requester must present about itself.">Required credential types</Label>
          <input
            value={req.credentialTypes.join(', ')}
            onChange={(e) => update((p) => (p.require.credentialTypes = e.target.value.split(',').map((s) => s.trim()).filter(Boolean)))}
            className="w-full rounded-lg border border-line-2 bg-surface-2 px-3 py-1.5 text-sm mono outline-none focus:border-accent/60"
          />
        </div>
        <div>
          <Label hint="Minimum number of cryptographically verified counterparty attestations. Set to 1: the Rogue bot (no history) fails even if you trust its issuer; the Buyer (2 attestations) passes.">Min verified attestations</Label>
          <input
            type="number"
            min={0}
            value={req.minVerifiedAttestations}
            onChange={(e) => update((p) => (p.require.minVerifiedAttestations = Math.max(0, Number(e.target.value) || 0)))}
            className="w-full rounded-lg border border-line-2 bg-surface-2 px-3 py-1.5 text-sm tabular-nums outline-none focus:border-accent/60"
          />
        </div>

        <div className="col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-y-2.5 gap-x-4 pt-1">
          <Toggle checked={req.identityProof} onChange={(v) => update((p) => (p.require.identityProof = v))} label="Require identity proof (request signature)" hint="Turning this off is how you get spoofed. Left on for every sane policy." />
          <Toggle checked={req.rejectReusedNonce} onChange={(v) => update((p) => (p.require.rejectReusedNonce = v))} label="Reject reused nonces" hint="Replay defense. Off = the replay attack succeeds." />
          <Toggle checked={req.notRevoked} onChange={(v) => update((p) => (p.require.notRevoked = v))} label="Check revocation status" hint="Fetch and verify the issuer's signed status list." />
          <Toggle checked={req.authority.principalMustBeCredentialController} onChange={(v) => update((p) => (p.require.authority.principalMustBeCredentialController = v))} label="Grant principal must be attested controller" hint="Binds delegated authority to the controller the issuer attested. Off = anyone could 'delegate' to anyone." />
          <Toggle checked={req.audienceMatch} onChange={(v) => update((p) => (p.require.audienceMatch = v))} label="Require audience match" hint="The request must name this verifier as recipient." />
        </div>
      </div>

      {showJson && (
        <div className="mt-4 animate-fade-up">
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            spellCheck={false}
            className="w-full h-64 rounded-lg border border-line-2 bg-[#0b1016] p-3 mono text-[11.5px] leading-[1.5] text-fg-2 outline-none focus:border-accent/60"
          />
          <div className="mt-2 flex items-center gap-2">
            <Button
              size="sm"
              onClick={() => {
                try {
                  const parsed = JSON.parse(draft) as Policy;
                  if (!parsed.policyId || !parsed.require) throw new Error('policyId and require are mandatory');
                  setJsonError(null);
                  setPolicy(parsed);
                } catch (e) {
                  setJsonError((e as Error).message);
                }
              }}
            >
              Apply JSON
            </Button>
            {jsonError && <span className="text-xs text-bad">{jsonError}</span>}
          </div>
        </div>
      )}
    </Card>
  );
}
