'use client';
import { useEffect } from 'react';
import { X } from 'lucide-react';
import { JsonView } from '../JsonView';
import { cx } from '../ui';
import { useTrustGate, type DrawerTab } from '../store';
import { resolveDidKey } from '@/lib/identity/did-key';

const TABS: Array<{ id: DrawerTab; label: string }> = [
  { id: 'decision', label: 'Decision' },
  { id: 'receipt', label: 'Signed receipt' },
  { id: 'request', label: 'Request envelope' },
  { id: 'credential', label: 'Credential (VC)' },
  { id: 'grant', label: 'Capability grant' },
  { id: 'attestations', label: 'Attestations' },
  { id: 'statusList', label: 'Status list' },
  { id: 'policy', label: 'Policy' },
  { id: 'didDocument', label: 'DID document' },
];

const BLURB: Record<DrawerTab, string> = {
  decision: 'Structured decision: allow, policy_id, checks[], failed_checks[], explanation, evidence refs, timestamp. This is what the verifier returns to the requesting agent.',
  receipt: 'DecisionReceipt signed by the verifier (eddsa-jcs-2022). Bound to requestHash + policyHash so the decision is auditable later.',
  request: 'The exact bytes that crossed between agents: the ActionRequest, its presentation (VC, grant, attestations) and the requester’s proof.',
  credential: 'W3C VC 2.0 with a Data Integrity proof. Change any byte and the proof breaks.',
  grant: 'Capability grant signed by the principal. RFC 9396-style authorization details with action/resource/amount/time constraints.',
  attestations: 'Counterparty-signed statements about past actions. Verified individually; counted as evidence.',
  statusList: 'Issuer-signed Bitstring Status List. The credential points at index N; bit N set = revoked.',
  policy: 'Declarative, verifier-local policy. Edit it in the Policy Editor.',
  didDocument: 'DID Document resolved from the requester’s did:key. The Multikey is the identity.',
};

export function JsonDrawer() {
  const open = useTrustGate((s) => s.drawerOpen);
  const tab = useTrustGate((s) => s.drawerTab);
  const current = useTrustGate((s) => s.current);
  const policy = useTrustGate((s) => s.policy);
  const world = useTrustGate((s) => s.world);
  const { closeDrawer, openDrawer } = useTrustGate();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && closeDrawer();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, closeDrawer]);

  if (!open) return null;
  const req = current?.request;
  const vc = req?.presentation.credentials[0] ?? world.agents.buyer.credentials[0];
  const statusList = vc?.credentialStatus ? world.verifier.resolveStatusList(vc.credentialStatus.statusListCredential) : undefined;
  const value: unknown = (() => {
    switch (tab) {
      case 'decision': {
        if (!current) return { note: 'No decision yet' };
        const { receipt, ...rest } = current.decision;
        void receipt;
        return rest;
      }
      case 'receipt':
        return current?.decision.receipt ?? { note: 'No decision yet' };
      case 'request':
        return req ?? { note: 'No request yet' };
      case 'credential':
        return vc ?? { note: 'No credential presented' };
      case 'grant':
        return req?.presentation.grants[0] ?? world.agents.buyer.grants[0];
      case 'attestations':
        return req?.presentation.attestations ?? world.agents.buyer.attestations;
      case 'statusList':
        return statusList ?? { note: 'No status list' };
      case 'policy':
        return policy;
      case 'didDocument':
        return resolveDidKey(req?.from ?? world.agents.buyer.did)?.document ?? { note: 'unresolvable' };
    }
  })();

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal>
      <button type="button" aria-label="Close" className="absolute inset-0 bg-black/50 backdrop-blur-[2px]" onClick={closeDrawer} />
      <aside className="relative h-full w-full max-w-2xl bg-surface border-l border-line shadow-2xl flex flex-col animate-fade-up">
        <header className="flex items-center gap-3 px-4 h-12 border-b border-line">
          <span className="text-sm font-semibold">Raw evidence</span>
          <span className="text-[11px] text-muted">for technical judges — every object below is real signed JSON</span>
          <button type="button" onClick={closeDrawer} className="ml-auto text-muted hover:text-fg" aria-label="Close drawer">
            <X className="size-4" />
          </button>
        </header>
        <div className="flex gap-1 px-3 py-2 border-b border-line overflow-x-auto">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => openDrawer(t.id)}
              className={cx('shrink-0 rounded-md px-2.5 h-7 text-xs transition-colors', tab === t.id ? 'bg-surface-3 text-fg' : 'text-muted hover:text-fg')}
            >
              {t.label}
            </button>
          ))}
        </div>
        <p className="px-4 pt-3 text-xs text-muted">{BLURB[tab]}</p>
        <div className="p-4 overflow-auto flex-1">
          <JsonView value={value} maxHeight="max-h-none" title={TABS.find((t) => t.id === tab)?.label} />
        </div>
      </aside>
    </div>
  );
}
