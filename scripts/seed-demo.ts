/**
 * Seed script: regenerates the deterministic demo fixtures and writes the
 * PUBLIC evidence bundle to data/demo-fixtures.json.
 *
 *   npm run seed
 *
 * Re-running it is idempotent: the file is byte-identical every time because
 * every demo key derives from a labelled SHA-256 seed and every fixture carries
 * a fixed timestamp (see lib/demo/seeds.ts). Secret keys are never written.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createDemoWorld } from '../lib/demo/world';
import { exportWorld } from '../lib/demo/export';
import { jcs } from '../lib/crypto/canonicalize';
import { sha256Hex } from '../lib/crypto/hash';

const world = createDemoWorld();
const bundle = exportWorld(world);
const outDir = join(process.cwd(), 'data');
mkdirSync(outDir, { recursive: true });
const outFile = join(outDir, 'demo-fixtures.json');
writeFileSync(outFile, JSON.stringify(bundle, null, 2) + '\n');

console.log('TrustGate demo fixtures written to', outFile);
console.log('bundle sha256:', sha256Hex(jcs(bundle)));
for (const a of bundle.actors) console.log('  ' + a.role.padEnd(12), a.name.padEnd(28), a.did);
