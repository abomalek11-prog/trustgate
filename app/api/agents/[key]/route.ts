/** GET /api/agents/:key — one agent's Trust Profile by key (buyer|procurement|clone|rogue) or by DID. */
import { NextResponse } from 'next/server';
import { serverWorld } from '@/lib/server/world';
import { publicAgent } from '@/lib/demo/export';
import { findAgentByDid, type AgentKey } from '@/lib/demo/world';

export const dynamic = 'force-dynamic';

export async function GET(_req: Request, ctx: { params: Promise<{ key: string }> }) {
  const { key } = await ctx.params;
  const world = serverWorld();
  const agent = world.agents[key as AgentKey] ?? findAgentByDid(world, decodeURIComponent(key));
  if (!agent) return NextResponse.json({ error: 'Unknown agent: ' + key }, { status: 404 });
  return NextResponse.json(publicAgent(agent));
}
