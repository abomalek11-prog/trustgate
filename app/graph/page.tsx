import type { Metadata } from 'next';
import { GraphPage } from '@/components/graph/GraphPage';

export const metadata: Metadata = { title: 'Agent Graph — TrustGate' };

export default function Page() {
  return <GraphPage />;
}
