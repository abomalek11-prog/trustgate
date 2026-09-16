/** GET /api/demo/fixtures — the live public evidence bundle (same shape as data/demo-fixtures.json). */
import { NextResponse } from 'next/server';
import { serverWorld } from '@/lib/server/world';
import { exportWorld } from '@/lib/demo/export';

export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json(exportWorld(serverWorld()));
}
