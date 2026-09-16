/** GET /api/agents — the Agent Directory as JSON (public data only; no secret keys). */
import { NextResponse } from 'next/server';
import { serverWorld } from '@/lib/server/world';
import { publicActor, publicAgent } from '@/lib/demo/export';
import { allActors } from '@/lib/demo/world';

export const dynamic = 'force-dynamic';

export async function GET() {
  const world = serverWorld();
  return NextResponse.json({
    agents: Object.values(world.agents).map(publicAgent),
    actors: allActors(world).map(publicActor),
    verifier: world.agents.procurement.did,
  });
}
