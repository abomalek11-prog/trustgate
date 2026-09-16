/**
 * POST /api/demo/revoke  Body: { "credentialId": "urn:uuid:...", "revoked": true|false }
 * The issuer re-signs its status list. Subsequent /api/gate calls see the change.
 */
import { NextResponse } from 'next/server';
import { serverWorld } from '@/lib/server/world';
import { setCredentialRevoked } from '@/lib/demo/world';
import { revokedIndices } from '@/lib/credentials/status-list';

export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  let body: { credentialId?: string; revoked?: boolean };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: 'Body must be JSON: { credentialId, revoked }' }, { status: 400 });
  }
  const world = serverWorld();
  const all = Object.values(world.agents).flatMap((a) => a.credentials);
  const vc = all.find((c) => c.id === body.credentialId);
  if (!vc) return NextResponse.json({ error: 'Unknown credentialId', known: all.map((c) => c.id) }, { status: 404 });
  const revoked = body.revoked !== false;
  setCredentialRevoked(world, vc, revoked);
  const issuer = Object.values(world.issuers).find((i) => i.did === vc.issuer)!;
  return NextResponse.json({ credentialId: vc.id, revoked, statusList: issuer.statusList, revokedIndices: revokedIndices(issuer.statusList) });
}
