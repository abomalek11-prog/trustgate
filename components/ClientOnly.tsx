'use client';
import { useSyncExternalStore, type ReactNode } from 'react';

/** Renders children only after hydration — the demo world (keys, nonce cache) lives in the browser. */
export function ClientOnly({ children, fallback }: { children: ReactNode; fallback?: ReactNode }) {
  const mounted = useSyncExternalStore(
    () => () => {},
    () => true,
    () => false,
  );
  if (!mounted)
    return (
      fallback ?? (
        <div className="grid place-items-center py-24 text-sm text-muted">
          <span className="animate-pulse-soft">Generating deterministic demo identities and signing fixtures in your browser…</span>
        </div>
      )
    );
  return <>{children}</>;
}
