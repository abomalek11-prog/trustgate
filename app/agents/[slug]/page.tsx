import type { Metadata } from 'next';
import { TrustProfile } from '@/components/agents/TrustProfile';
import { AGENT_KEYS } from '@/lib/demo/world';

export const metadata: Metadata = { title: 'Agent Trust Profile — TrustGate' };

export function generateStaticParams() {
  return AGENT_KEYS.map((slug) => ({ slug }));
}

export default async function AgentProfilePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return <TrustProfile slug={slug} />;
}
