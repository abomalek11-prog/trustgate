/**
 * GET /api/demo/request?scenario=<id>&amount=<usd>
 *
 * Builds (but does not evaluate) a freshly signed ActionRequest for a scenario
 * so you can pipe it straight into POST /api/gate:
 *
 *   curl -s "$HOST/api/demo/request?scenario=spoofed" | curl -s -X POST -H 'content-type: application/json' -d @- "$HOST/api/gate"
 *
 * Stateless scenarios: valid, spoofed, overscope, tampered, forged-grant,
 * untrusted-issuer, stale, expired-grant, no-authority, borrowed-credential.
 * Stateful ones are driven differently: `revoked` via POST /api/demo/revoke,
 * `replay` by POSTing the same envelope to /api/gate twice.
 */
import { NextResponse } from 'next/server';
import { serverWorld } from '@/lib/server/world';
import {
  buildRequestFor,
  forgedGrant,
  presentationFor,
  tamperedCredential,
  SCENARIO_BY_ID,
  type ScenarioId,
} from '@/lib/demo/scenarios';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const url = new URL(req.url);
  const id = (url.searchParams.get('scenario') ?? 'valid') as ScenarioId;
  const scenario = SCENARIO_BY_ID[id];
  if (!scenario) {
    return NextResponse.json({ error: 'Unknown scenario', known: Object.keys(SCENARIO_BY_ID) }, { status: 400 });
  }
  const amountParam = url.searchParams.get('amount');
  const amount = amountParam ? Number(amountParam) : scenario.amount;
  if (!Number.isFinite(amount) || amount <= 0) {
    return NextResponse.json({ error: 'amount must be a positive number' }, { status: 400 });
  }

  const world = serverWorld();
  const buyer = world.agents.buyer;
  const now = new Date();
  const base = { requester: scenario.requester, amount, now } as const;

  const request = (() => {
    switch (id) {
      case 'tampered':
        return buildRequestFor(world, {
          ...base,
          presentation: { ...presentationFor(buyer), credentials: [tamperedCredential(buyer.credentials[0])] },
        });
      case 'forged-grant':
        return buildRequestFor(world, { ...base, presentation: { ...presentationFor(buyer), grants: [forgedGrant(buyer.grants[0])] } });
      case 'stale':
        return buildRequestFor(world, { ...base, issuedAt: new Date(now.getTime() - 300_000) });
      case 'expired-grant':
        return buildRequestFor(world, { ...base, presentation: { ...presentationFor(buyer), grants: [world.expiredGrant] } });
      case 'no-authority':
        return buildRequestFor(world, { ...base, presentation: { ...presentationFor(buyer), grants: [] } });
      case 'borrowed-credential':
        return buildRequestFor(world, { ...base, presentation: presentationFor(buyer) });
      default:
        return buildRequestFor(world, base);
    }
  })();

  return NextResponse.json({
    request,
    scenario: { id: scenario.id, title: scenario.title, expected: scenario.expected, defense: scenario.defense },
  });
}
