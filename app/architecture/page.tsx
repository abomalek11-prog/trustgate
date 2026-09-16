import type { Metadata } from 'next';
import { Architecture } from '@/components/architecture/Architecture';

export const metadata: Metadata = { title: 'Architecture & Thesis — TrustGate' };

export default function ArchitecturePage() {
  return <Architecture />;
}
