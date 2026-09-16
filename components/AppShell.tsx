'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ShieldCheck, Code2, ArrowRight } from 'lucide-react';
import type { ReactNode } from 'react';
import { cx } from './ui';
import { useTrustGate } from './store';
import type { Stage } from '@/lib/policy/types';

const NAV = [
  { href: '/', label: 'Console' },
  { href: '/agents', label: 'Agents' },
  { href: '/architecture', label: 'Architecture' },
];

const PIPELINE: Array<{ label: string; stages: Stage[] }> = [
  { label: 'Identity', stages: ['identity', 'signature', 'freshness'] },
  { label: 'Claims', stages: ['credential', 'issuer', 'revocation', 'authority', 'history'] },
  { label: 'Verification', stages: ['credential', 'issuer', 'revocation', 'authority', 'history'] },
  { label: 'Policy', stages: ['policy'] },
  { label: 'Decision Receipt', stages: [] },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const running = useTrustGate((s) => s.running);
  const live = useTrustGate((s) => s.liveChecks);
  const current = useTrustGate((s) => s.current);
  const activeStage = running ? live[live.length - 1]?.stage : undefined;

  return (
    <div className="min-h-full flex flex-col">
      <header className="sticky top-0 z-40 border-b border-line bg-bg/85 backdrop-blur">
        <div className="mx-auto max-w-[1440px] px-4 sm:px-6 h-14 flex items-center gap-3 sm:gap-6 overflow-x-auto">
          <Link href="/" className="flex items-center gap-2.5 shrink-0">
            <span className="grid place-items-center size-8 rounded-lg bg-accent-bg border border-accent/30">
              <ShieldCheck className="size-4 text-accent" />
            </span>
            <span className="leading-tight">
              <span className="block text-[15px] font-semibold tracking-tight">TrustGate</span>
              <span className="hidden sm:block text-[10.5px] text-muted -mt-0.5">The agent that earns trust</span>
            </span>
          </Link>
          <nav className="flex items-center gap-1 shrink-0">
            {NAV.map((n) => {
              const active = n.href === '/' ? pathname === '/' : pathname.startsWith(n.href);
              return (
                <Link
                  key={n.href}
                  href={n.href}
                  className={cx('px-3 h-8 inline-flex items-center rounded-md text-sm transition-colors', active ? 'bg-surface-3 text-fg' : 'text-fg-2 hover:text-fg hover:bg-surface-2')}
                >
                  {n.label}
                </Link>
              );
            })}
          </nav>
          <div className="ml-auto hidden md:flex items-center gap-3 text-[11px] text-muted">
            <span className="inline-flex items-center gap-1.5 rounded-md border border-line-2 px-2 h-7 mono">
              <span className={cx('size-1.5 rounded-full', running ? 'bg-warn animate-pulse-soft' : 'bg-ok')} />
              engine: in-browser Ed25519 · did:key · VC 2.0
            </span>
            <a href={process.env.NEXT_PUBLIC_REPO_URL ?? "https://github.com/"} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 hover:text-fg" title="Repository">
              <Code2 className="size-4" />
            </a>
          </div>
        </div>
        <div className="border-t border-line/70 bg-surface/60">
          <div className="mx-auto max-w-[1440px] px-4 sm:px-6 h-8 flex items-center gap-2 overflow-x-auto text-[11px] mono text-muted">
            <span className="mr-1 uppercase tracking-wider text-[10px]">Pipeline</span>
            {PIPELINE.map((p, i) => {
              const on = activeStage ? p.stages.includes(activeStage) : false;
              const done = !running && current && (p.label !== 'Decision Receipt' || current.decision.receipt);
              return (
                <span key={p.label} className="inline-flex items-center gap-2">
                  <span
                    className={cx(
                      'rounded px-1.5 py-0.5 border transition-colors',
                      on ? 'border-accent/50 text-accent bg-accent-bg' : done ? 'border-line-2 text-fg-2' : 'border-transparent',
                    )}
                  >
                    {p.label}
                  </span>
                  {i < PIPELINE.length - 1 && <ArrowRight className="size-3 opacity-60" />}
                </span>
              );
            })}
            <span className="ml-auto hidden sm:inline text-[10.5px]">trust = evidence ∧ authority ∧ policy — never a score</span>
          </div>
        </div>
      </header>
      <main className="flex-1 mx-auto w-full max-w-[1440px] px-4 sm:px-6 py-5">{children}</main>
      <footer className="border-t border-line mt-8">
        <div className="mx-auto max-w-[1440px] px-4 sm:px-6 py-4 text-[11px] text-muted flex flex-wrap gap-x-6 gap-y-1">
          <span>TrustGate · DOO Builders League · “The Agent That Earns Trust”</span>
          <span>Standards: W3C DID Core (did:key), W3C VC 2.0 + Data Integrity eddsa-jcs-2022, Bitstring Status List, RFC 9396 authorization details, RFC 8785 JCS</span>
          <span className="ml-auto">All demo identities are synthetic and deterministic — no secrets.</span>
        </div>
      </footer>
    </div>
  );
}
