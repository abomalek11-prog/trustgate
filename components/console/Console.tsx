'use client';
import { InteractionConsole } from './InteractionConsole';
import { DecisionCard } from './DecisionCard';
import { VerificationTrace } from './VerificationTrace';
import { AttackLab } from './AttackLab';
import { PolicyEditor } from './PolicyEditor';
import { ActivityLog } from './ActivityLog';
import { JsonDrawer } from './JsonDrawer';
import { ClientOnly } from '../ClientOnly';

export function Console() {
  return (
    <ClientOnly>
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        <div className="xl:col-span-5 space-y-5">
          <InteractionConsole />
          <AttackLab />
          <PolicyEditor />
        </div>
        <div className="xl:col-span-7 space-y-5 xl:sticky xl:top-[6.5rem]">
          <DecisionCard />
          <VerificationTrace />
          <ActivityLog />
        </div>
      </div>
      <JsonDrawer />
    </ClientOnly>
  );
}
