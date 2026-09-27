// The saved credentials in the component tests: records as the server gave
// them (the goldens' register-complete answers), put in the browser's storage
// both UIs read; and the server routes the list's warm-up asks.
import { goldenAnswers } from '@legacy-tests/simple/ceremony-answers.js';
import { seedUnifiedCredentialRecords } from '@legacy/shared/storage/local/storage-core.js';

import { json, type Route } from './fetch';

export const STORAGE_KEY = 'postquantum-webauthn.credentials';

type Answer = { request: string; status: number; body: Record<string, unknown> };

/** The golden scenario's answers, in order. */
export function answersOf(scenario: string): Answer[] {
  return goldenAnswers(scenario) as Answer[];
}

/** The credential a golden registration saved, typed as the browser keeps it. */
export function savedRecord(scenario: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const answer = answersOf(scenario).find((entry) => entry.request.includes('/register/complete') && entry.status === 200)!;
  const stored = answer.body.storedCredential as Record<string, unknown>;
  return { ...stored, type: scenario.startsWith('advanced') ? 'advanced' : 'simple', ...extra };
}

/**
 * Empties the browser's storage, or keeps `records` in it, and forgets what
 * the storage read before: it keeps what it read for the page's life.
 */
export function keepRecords(records: object[] = []) {
  window.localStorage.clear();
  seedUnifiedCredentialRecords(null);
  if (records.length) window.localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
}

export function storedRecords(): Record<string, unknown>[] {
  return JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? '[]');
}

/** The routes the list's warm-up asks: no snapshot to add, nothing to upload. */
export function warmUpRoutes(): Record<string, Route> {
  return {
    '/api/advanced/credential-artifacts/bulk': () => json({ artifacts: {} }),
  };
}
