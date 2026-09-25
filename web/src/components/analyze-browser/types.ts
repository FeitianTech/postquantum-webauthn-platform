import type { gatherAnalysis } from '@legacy/shared/browser/report.js';

// The shapes the logic modules return, named for the views. The modules are the
// only implementation; these types only narrow what TypeScript infers from them.
export type FactState = 'yes' | 'no' | 'unavailable' | 'undetermined';
export type Fact = { state: FactState; note?: string };
export type Capability = Fact & { key: string; kind: 'defined' | 'extension' | 'unrecognised'; label: string };
export type ClientCapabilities = Fact & {
  returned: Record<string, unknown> | null;
  capabilities: Capability[];
  omitted: string[];
};
export type Analysis = Awaited<ReturnType<typeof gatherAnalysis>>;
