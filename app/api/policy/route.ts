/**
 * GET /api/policy  — the verifier's current policy.
 * PUT /api/policy  — replace it (demo only; per server instance). Body: Policy JSON.
 */
import { NextResponse } from 'next/server';
import { serverWorld } from '@/lib/server/world';
import type { Policy } from '@/lib/policy/types';
import { hashDocument } from '@/lib/crypto/hash';

export const dynamic = 'force-dynamic';

export async function GET() {
  const world = serverWorld();
  return NextResponse.json({ policy: world.verifier.policy, policyHash: hashDocument(world.verifier.policy) });
}

export async function PUT(req: Request) {
  let policy: Policy;
  try {
    policy = (await req.json()) as Policy;
  } catch {
    return NextResponse.json({ error: 'Body must be a Policy JSON document' }, { status: 400 });
  }
  if (!policy?.policyId || !policy.require) return NextResponse.json({ error: 'Invalid policy' }, { status: 400 });
  const world = serverWorld();
  world.verifier.setPolicy(policy);
  return NextResponse.json({ policy, policyHash: hashDocument(policy) });
}
