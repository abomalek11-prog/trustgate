/**
 * Server-side demo world (used by the API routes). One instance per server
 * process; survives dev HMR via globalThis. On serverless hosts state such as
 * the nonce cache and revocation flags is per-instance and best-effort — the
 * browser console is the canonical, fully stateful demo.
 */
import { createDemoWorld, type DemoWorld } from '../demo/world';

const g = globalThis as typeof globalThis & { __trustgateWorld?: DemoWorld };

export function serverWorld(): DemoWorld {
  if (!g.__trustgateWorld) g.__trustgateWorld = createDemoWorld();
  return g.__trustgateWorld;
}

export function resetServerWorld(): DemoWorld {
  g.__trustgateWorld = createDemoWorld();
  return g.__trustgateWorld;
}
