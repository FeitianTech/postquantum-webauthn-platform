// What the result panel under a tab's buttons says about the last ceremony comes
// from the module both UIs share: frontend/static/scripts/shared/ceremony/result.js.
import { describeCeremonyResult } from '@legacy/shared/ceremony/result.js';

/** What a tab hands the panel: the server's verdicts and the tab's consequence. */
export type CeremonyResultInput = {
  title?: string;
  signCount?: number;
  signCountStatus?: string | null;
  consequence?: string;
  showChallenge?: boolean;
  challengeSource?: string | null;
  challengeStatus?: string | null;
};

export type CeremonyResultRow = { label: string; value: string | null; text: string; after: string | null };
export type CeremonyResultView = { title: string; rows: CeremonyResultRow[]; warning: boolean };

export const describeResultPanel = describeCeremonyResult as (result: CeremonyResultInput) => CeremonyResultView | null;
