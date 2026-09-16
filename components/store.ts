'use client';
/**
 * Client-side state for the demo. The engine (lib/) runs IN THE BROWSER:
 * every signature you see verified in the trace was verified by
 * @noble/ed25519 on the judge's own machine, milliseconds ago.
 *
 * The world object is a mutable class instance; `version` is bumped after each
 * mutation so React re-renders.
 */
import { create } from 'zustand';
import { createDemoWorld, setCredentialRevoked, type AgentKey, type DemoWorld } from '@/lib/demo/world';
import { buildRequestFor, DEFAULT_RESOURCE, runScenario, SCENARIO_BY_ID, type ScenarioId, type ScenarioRun } from '@/lib/demo/scenarios';
import { recordOutcome } from '@/lib/demo/outcome';
import { isRevoked } from '@/lib/credentials/status-list';
import type { Check, Decision, Policy } from '@/lib/policy/types';
import type { ActionRequest } from '@/lib/requests/types';

export interface RunRecord {
  id: number;
  at: string;
  /** scenario id when triggered from the Attack Lab */
  scenarioId?: ScenarioId;
  requester: AgentKey;
  amount: number;
  resource: string;
  request: ActionRequest;
  decision: Decision;
  priorSteps: ScenarioRun['priorSteps'];
  note: string;
}

export type DrawerTab = 'decision' | 'receipt' | 'request' | 'credential' | 'grant' | 'attestations' | 'statusList' | 'policy' | 'didDocument';

interface TrustGateState {
  world: DemoWorld;
  version: number;
  // console form
  requester: AgentKey;
  amount: number;
  resource: string;
  // execution
  running: boolean;
  liveChecks: Check[];
  current: RunRecord | null;
  log: RunRecord[];
  // policy
  policy: Policy;
  // drawer
  drawerOpen: boolean;
  drawerTab: DrawerTab;
  /** ms per check in the animated trace (0 = instant) */
  stepDelayMs: number;

  setRequester: (r: AgentKey) => void;
  setAmount: (n: number) => void;
  setResource: (s: string) => void;
  sendRequest: () => Promise<void>;
  runScenario: (id: ScenarioId) => Promise<void>;
  rerunLast: () => Promise<void>;
  setPolicy: (p: Policy) => void;
  resetPolicy: () => void;
  setBuyerRevoked: (revoked: boolean) => void;
  buyerRevoked: () => boolean;
  reset: () => void;
  openDrawer: (tab?: DrawerTab) => void;
  closeDrawer: () => void;
  setStepDelay: (ms: number) => void;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
let runCounter = 0;
let policyTimer: ReturnType<typeof setTimeout> | null = null;

function initialWorld() {
  return createDemoWorld();
}

export const useTrustGate = create<TrustGateState>((set, get) => {
  const world = initialWorld();
  const defaultPolicy = JSON.parse(JSON.stringify(world.policy)) as Policy;

  const runWithTrace = async (exec: (onCheck: (c: Check) => Promise<void>) => Promise<Omit<RunRecord, 'id' | 'at'>>) => {
    if (get().running) return;
    set({ running: true, liveChecks: [], current: null });
    const onCheck = async (c: Check) => {
      set((s) => ({ liveChecks: [...s.liveChecks, c] }));
      const d = get().stepDelayMs;
      if (d > 0) await sleep(d);
    };
    try {
      const partial = await exec(onCheck);
      const record: RunRecord = { ...partial, id: ++runCounter, at: new Date().toISOString() };
      recordOutcome(get().world, record.request, record.decision);
      set((s) => ({ current: record, log: [record, ...s.log].slice(0, 50), running: false, version: s.version + 1 }));
    } catch (e) {
      console.error(e);
      set({ running: false });
    }
  };

  return {
    world,
    version: 0,
    requester: 'buyer',
    amount: 250,
    resource: DEFAULT_RESOURCE,
    running: false,
    liveChecks: [],
    current: null,
    log: [],
    policy: world.policy,
    drawerOpen: false,
    drawerTab: 'decision',
    stepDelayMs: 75,

    setRequester: (requester) => set({ requester }),
    setAmount: (amount) => set({ amount: Number.isFinite(amount) && amount > 0 ? amount : 0 }),
    setResource: (resource) => set({ resource }),

    sendRequest: async () => {
      const { world, requester, amount, resource } = get();
      if (!amount) return;
      await runWithTrace(async (onCheck) => {
        const request = buildRequestFor(world, { requester, amount, resource, now: new Date() });
        const decision = await world.verifier.gate(request, { onCheck });
        return { requester, amount, resource, request, decision, priorSteps: [], note: '' };
      });
    },

    runScenario: async (id) => {
      const { world } = get();
      const s = SCENARIO_BY_ID[id];
      set({ requester: s.requester, amount: s.amount, resource: DEFAULT_RESOURCE });
      await runWithTrace(async (onCheck) => {
        const run = await runScenario(world, id, { onCheck });
        return {
          scenarioId: id,
          requester: s.requester,
          amount: s.amount,
          resource: DEFAULT_RESOURCE,
          request: run.request,
          decision: run.decision,
          priorSteps: run.priorSteps,
          note: run.note,
        };
      });
    },

    rerunLast: async () => {
      const { current, runScenario: runSc, sendRequest } = get();
      if (!current) return;
      if (current.scenarioId) await runSc(current.scenarioId);
      else await sendRequest();
    },

    setPolicy: (p) => {
      const { world } = get();
      world.verifier.setPolicy(p);
      set((s) => ({ policy: p, version: s.version + 1 }));
      // A judge edits a field -> the last interaction is re-run under the new policy.
      if (policyTimer) clearTimeout(policyTimer);
      policyTimer = setTimeout(() => {
        if (get().current && !get().running) void get().rerunLast();
      }, 450);
    },

    resetPolicy: () => get().setPolicy(JSON.parse(JSON.stringify(defaultPolicy)) as Policy),

    setBuyerRevoked: (revoked) => {
      const { world } = get();
      setCredentialRevoked(world, world.agents.buyer.credentials[0], revoked, new Date());
      set((s) => ({ version: s.version + 1 }));
    },

    buyerRevoked: () => {
      const { world } = get();
      const vc = world.agents.buyer.credentials[0];
      return isRevoked(world.issuers.verdant.statusList, Number(vc.credentialStatus!.statusListIndex));
    },

    reset: () => {
      const fresh = initialWorld();
      set({ world: fresh, policy: fresh.policy, current: null, liveChecks: [], log: [], requester: 'buyer', amount: 250, resource: DEFAULT_RESOURCE, version: 0 });
    },

    openDrawer: (tab) => set({ drawerOpen: true, ...(tab ? { drawerTab: tab } : {}) }),
    closeDrawer: () => set({ drawerOpen: false }),
    setStepDelay: (stepDelayMs) => set({ stepDelayMs }),
  };
});

/** Convenience selectors */
export const useWorld = () => useTrustGate((s) => s.world);
export const useVersion = () => useTrustGate((s) => s.version);
