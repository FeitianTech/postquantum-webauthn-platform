// The saved credentials in the component tests: records as the server gave
// them (the goldens' register-complete answers), put in the browser's storage
// both UIs read; and the server routes the list's warm-up asks.
import { goldenAnswers, goldenArtifact } from '@legacy-tests/simple/ceremony-answers.js';
import { seedUnifiedCredentialRecords } from '@legacy/shared/storage/local/storage-core.js';

import { json, type Route } from './fetch';

export const STORAGE_KEY = 'postquantum-webauthn.credentials';

type Answer = { request: string; status: number; body: Record<string, unknown> };


/** The golden scenario's answers, in order. */
export function answersOf(scenario: string): Answer[] {
  return goldenAnswers(scenario) as Answer[];
}

/** The credential a golden registration saved (the scenario's `index`th), typed as the browser keeps it. */
export function savedRecord(scenario: string, extra: Record<string, unknown> = {}, index = 0): Record<string, unknown> {
  const answer = answersOf(scenario).filter((entry) => entry.request.includes('/register/complete') && entry.status === 200)[index];
  const stored = answer.body.storedCredential as Record<string, unknown>;
  return { ...stored, type: scenario.startsWith('advanced') ? 'advanced' : 'simple', ...extra };
}

// 'registration-detail-decodes' registers four credentials (ES256, EdDSA,
// ML-DSA-65, packed with a certificate), then asks the decoder for each one's
// attestation object, then for the first one's authenticator data.
export const DETAIL_SCENARIO = 'registration-detail-decodes';

/** The decoder's route as the server answered the credential details' questions, by the payload asked. */
export function decodeRoute(): Route {
  const answers = answersOf(DETAIL_SCENARIO);
  const registered = answers.filter((entry) => entry.request.includes('/register/complete')).map((entry) => entry.body.storedCredential as Record<string, string>);
  const decodes = answers.filter((entry) => entry.request === 'POST /api/decode');
  const byPayload = new Map<string, Answer>();
  registered.forEach((record, index) => byPayload.set(record.attestationObject, decodes[index]));
  byPayload.set(registered[0].authenticatorData, decodes[registered.length]);
  return (init) => {
    const payload = JSON.parse(String(init?.body)).payload as string;
    const answer = byPayload.get(payload);
    return answer ? json(answer.body, answer.status) : json({ error: 'The payload is not valid CBOR.' }, 422);
  };
}

/** The artifact the server stored for a golden advanced registration, as GET …/credential-artifacts/<id> answers it. */
export const artifactAnswer = goldenArtifact as (scenario: string) => { storageId: string; artifact: Record<string, unknown> };

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
