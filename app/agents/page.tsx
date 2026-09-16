import type { Metadata } from 'next';
import { AgentDirectory } from '@/components/agents/AgentDirectory';

export const metadata: Metadata = { title: 'Agent Directory — TrustGate' };

export default function AgentsPage() {
  return <AgentDirectory />;
}
