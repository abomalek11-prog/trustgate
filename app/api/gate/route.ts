/**
 * POST /api/gate
 * The Procurement Agent's trust gate as an HTTP endpoint.
 *
 * Body: { "request": <signed ActionRequest>, "policy"?: <Policy>, "dryRun"?: boolean }
 * Returns the structured Decision (checks[], failed_checks[], explanation, receipt).
 *
 * Try it:
 *   curl -s "$HOST/api/demo/request?scenario=valid"   | curl -s -X POST -H 'content-type: application/json' -d @- "$HOST/api/gate"
 *   curl -s "$HOST/api/demo/request?scenario=spoofed" | curl -s -X POST -H 'content-type: application/json' -d @- "$HOST/api/gate"
 */
import { NextResponse } from 'next/server';
import { serverWorld } from '@/lib/server/world';
import type { ActionRequest } from '@/lib/requests/types';
import type { Policy } from '@/lib/policy/types';

export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  let body: { request?: ActionRequest; policy?: Policy; dryRun?: boolean };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: 'Body must be JSON: { request: ActionRequest, policy?: Policy }' }, { status: 400 });
  }
  const request = body.request ?? (body as unknown as ActionRequest);
  if (!request || typeof request !== 'object' || !('proof' in request)) {
    return NextResponse.json({ error: 'Missing signed ActionRequest (expected body.request with a proof)' }, { status: 400 });
  }
  const world = serverWorld();
  const decision = await world.verifier.gate(request, { policy: body.policy, dryRun: body.dryRun });
  return NextResponse.json(decision, { status: 200, headers: { 'x-trustgate-decision': decision.decision } });
}
