'use client';
import { useState, type ReactNode, type ButtonHTMLAttributes } from 'react';
import { Check, Copy, CircleCheck, CircleX, CircleMinus, TriangleAlert, Loader2 } from 'lucide-react';
import { shortDid } from '@/lib/identity/did-key';
import type { CheckStatus } from '@/lib/policy/types';

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

export function Card({ children, className, title, subtitle, actions }: { children: ReactNode; className?: string; title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <section className={cx('card', className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 px-5 pt-4 pb-3 border-b border-line">
          <div>
            {title && <h2 className="text-[13px] font-semibold tracking-wide uppercase text-fg-2">{title}</h2>}
            {subtitle && <p className="text-xs text-muted mt-0.5">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export type Tone = 'ok' | 'bad' | 'warn' | 'accent' | 'neutral';

const toneClass: Record<Tone, string> = {
  ok: 'bg-ok-bg text-ok border-ok/30',
  bad: 'bg-bad-bg text-bad border-bad/30',
  warn: 'bg-warn-bg text-warn border-warn/30',
  accent: 'bg-accent-bg text-accent border-accent/30',
  neutral: 'bg-surface-3 text-fg-2 border-line-2',
};

export function Badge({ tone = 'neutral', children, className, mono, tip }: { tone?: Tone; children: ReactNode; className?: string; mono?: boolean; tip?: string }) {
  return (
    <span
      data-tip={tip}
      className={cx('inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium leading-4', toneClass[tone], mono && 'mono', className)}
    >
      {children}
    </span>
  );
}

export function Button({
  variant = 'primary',
  size = 'md',
  className,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'ghost' | 'outline' | 'danger' | 'subtle'; size?: 'sm' | 'md' | 'lg' }) {
  const base = 'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/60';
  const sizes = { sm: 'h-7 px-2.5 text-xs', md: 'h-9 px-3.5 text-sm', lg: 'h-11 px-5 text-[15px]' };
  const variants = {
    primary: 'bg-accent-2 text-white hover:bg-accent shadow-[0_0_0_1px_rgba(143,157,255,0.35)]',
    ghost: 'bg-transparent text-fg-2 hover:bg-surface-3 hover:text-fg',
    outline: 'bg-transparent border border-line-2 text-fg-2 hover:bg-surface-3 hover:text-fg',
    subtle: 'bg-surface-3 text-fg-2 hover:bg-line-2 hover:text-fg border border-line-2',
    danger: 'bg-bad-bg text-bad border border-bad/30 hover:bg-bad/20',
  };
  return (
    <button className={cx(base, sizes[size], variants[variant], className)} {...rest}>
      {children}
    </button>
  );
}

export function CopyButton({ text, label = 'Copy', className }: { text: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={cx('inline-flex items-center gap-1 text-[11px] text-muted hover:text-fg transition-colors', className)}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* clipboard unavailable */
        }
      }}
      title="Copy to clipboard"
    >
      {done ? <Check className="size-3 text-ok" /> : <Copy className="size-3" />}
      {done ? 'Copied' : label}
    </button>
  );
}

export function Did({ did, label, className, tail = 6 }: { did: string; label?: string; className?: string; tail?: number }) {
  return (
    <span className={cx('inline-flex items-center gap-1.5', className)}>
      {label && <span className="text-fg-2">{label}</span>}
      <span className="mono text-[12px] text-fg-2" title={did}>
        {shortDid(did, tail)}
      </span>
      <CopyButton text={did} label="" />
    </span>
  );
}

export function StatusIcon({ status, className, size = 'size-4' }: { status: CheckStatus | 'pending' | 'running'; className?: string; size?: string }) {
  const c = cx(size, className);
  switch (status) {
    case 'pass':
      return <CircleCheck className={cx(c, 'text-ok')} aria-label="pass" />;
    case 'fail':
      return <CircleX className={cx(c, 'text-bad')} aria-label="fail" />;
    case 'warn':
      return <TriangleAlert className={cx(c, 'text-warn')} aria-label="warning" />;
    case 'skip':
      return <CircleMinus className={cx(c, 'text-muted')} aria-label="skipped" />;
    case 'running':
      return <Loader2 className={cx(c, 'text-accent animate-spin')} aria-label="running" />;
    default:
      return <span className={cx(c, 'rounded-full border border-line-2 inline-block')} aria-label="pending" />;
  }
}

export const toneForStatus: Record<CheckStatus, Tone> = { pass: 'ok', fail: 'bad', warn: 'warn', skip: 'neutral' };

export function Label({ children, hint }: { children: ReactNode; hint?: string }) {
  return (
    <label className="block text-[11px] font-medium uppercase tracking-wide text-muted mb-1.5">
      <span data-tip={hint} className={hint ? 'cursor-help border-b border-dotted border-line-2' : undefined}>
        {children}
      </span>
    </label>
  );
}

export function Toggle({ checked, onChange, label, hint }: { checked: boolean; onChange: (v: boolean) => void; label: ReactNode; hint?: string }) {
  return (
    <button type="button" role="switch" aria-checked={checked} onClick={() => onChange(!checked)} className="flex items-center gap-3 text-left group" data-tip={hint}>
      <span className={cx('relative h-5 w-9 rounded-full border transition-colors', checked ? 'bg-accent-2 border-accent' : 'bg-surface-3 border-line-2')}>
        <span className={cx('absolute top-0.5 size-4 rounded-full bg-white transition-all', checked ? 'left-[18px]' : 'left-0.5')} />
      </span>
      <span className="text-sm text-fg-2 group-hover:text-fg">{label}</span>
    </button>
  );
}

export function Money({ value }: { value: number }) {
  return <span className="tabular-nums">${value.toLocaleString('en-US')}</span>;
}

export function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function fmtDate(iso: string): string {
  return iso.replace('T', ' ').replace(/\.\d+Z$/, 'Z').replace(/Z$/, ' UTC');
}
