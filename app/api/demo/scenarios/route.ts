/**
 * GET  /api/demo/scenarios       — list Attack Lab scenarios
 * POST /api/demo/scenarios {id}  — run one server-side and return the full ScenarioRun
 */
import { NextResponse } from 'next/server';
import { serverWorld } from '@/lib/server/world';
import { runScenario, SCENARIOS, SCENARIO_BY_ID, type ScenarioId } from '@/lib/demo/scenarios';
import { recordOutcome } from '@/lib/demo/outcome';

export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json({ scenarios: SCENARIOS });
}

export async function POST(req: Request) {
  let body: { id?: ScenarioId };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: 'Body must be JSON: { id }' }, { status: 400 });
  }
  if (!body.id || !SCENARIO_BY_ID[body.id]) return NextResponse.json({ error: 'Unknown scenario', known: Object.keys(SCENARIO_BY_ID) }, { status: 400 });
  const world = serverWorld();
  const run = await runScenario(world, body.id);
  recordOutcome(world, run.request, run.decision);
  return NextResponse.json(run, { headers: { 'x-trustgate-decision': run.decision.decision } });
}
