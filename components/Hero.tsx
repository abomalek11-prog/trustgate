import Link from 'next/link';
import { ArrowRight } from 'lucide-react';

export function Hero() {
  return (
    <div className="mb-5 flex flex-col lg:flex-row lg:items-end gap-4">
      <div className="max-w-3xl">
        <h1 className="text-2xl sm:text-[28px] font-semibold tracking-tight leading-tight">
          Agents can act for us. The agent on the other side has no standard way to know <span className="text-accent">who</span> is asking, <span className="text-accent">what</span> they may do, or whether that is <span className="text-accent">still true</span>.
        </h1>
        <p className="mt-2 text-[14.5px] text-fg-2 max-w-2xl">
          TrustGate is TLS for agent behaviour: a receiving agent verifies key-bound identity, issuer-signed credentials, revocation, scoped delegated authority and request freshness, then applies its own policy. The result is ALLOW or DENY with the exact evidence that caused it — not a score.
        </p>
      </div>
      <div className="lg:ml-auto flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-muted">
        <Link href="/agents" className="inline-flex items-center gap-1 hover:text-fg">
          Agent directory <ArrowRight className="size-3" />
        </Link>
        <Link href="/graph" className="inline-flex items-center gap-1 hover:text-fg">
          Agent graph <ArrowRight className="size-3" />
        </Link>
        <Link href="/architecture" className="inline-flex items-center gap-1 hover:text-fg">
          Architecture &amp; thesis <ArrowRight className="size-3" />
        </Link>
        <a href="/api/demo/request?scenario=valid" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-fg mono">
          /api <ArrowRight className="size-3" />
        </a>
      </div>
    </div>
  );
}
