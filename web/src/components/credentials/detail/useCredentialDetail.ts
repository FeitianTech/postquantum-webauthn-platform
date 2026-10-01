import { useEffect, useRef, useState } from 'react';

import type { SavedCredential } from '../model';
import { type CredentialDetail, type RegistrationState, compose, hydrate, needsItsArtifact } from './model';

export type DetailPhase =
  | { phase: 'loading' }
  | { phase: 'ready'; detail: CredentialDetail; state: RegistrationState; hydrationFailed: boolean };

// Advanced records completed from their artifact, for the page's life, by
// storage id: the stored record is not changed here, and a copy would ask again
// at each opening. A failure is not kept, so the next opening asks again.
const hydrated = new Map<string, SavedCredential>();

function copyOf(record: SavedCredential): SavedCredential {
  return structuredClone(record);
}

async function completed(record: SavedCredential, onSaved: () => void) {
  if (!needsItsArtifact(record)) return { record, failed: false };
  const storageId = String(record.storageId || record.localStorageId || '');
  const known = storageId ? hydrated.get(storageId) : undefined;
  if (known) return { record: copyOf(known), failed: false };
  await hydrate(record, onSaved);
  const failed = record.__artifactHydrated === 'error';
  if (storageId && !failed) hydrated.set(storageId, copyOf(record));
  return { record, failed };
}

/**
 * A saved credential's details, composed once per opening: an advanced record
 * without its registration is first completed from its server artifact (the
 * snapshot it brings is saved, and `onSaved` called), then everything the
 * details show is composed, the decoder asked through decode-payload.js.
 */
export function useCredentialDetail(record: SavedCredential | null, key: string, onSaved: () => void): DetailPhase {
  const [result, setResult] = useState<{ key: string; phase: DetailPhase } | null>(null);
  const latest = useRef({ record, onSaved });
  latest.current = { record, onSaved };
  const found = Boolean(record);

  useEffect(() => {
    const shown = latest.current.record;
    if (!key || !shown) return undefined;
    let current = true;
    void (async () => {
      const { record: complete, failed } = await completed(copyOf(shown), () => latest.current.onSaved());
      const { detail, state } = await compose(complete);
      if (current) setResult({ key, phase: { phase: 'ready', detail, state, hydrationFailed: failed } });
    })();
    return () => {
      current = false;
    };
  }, [key, found]);

  return result && result.key === key ? result.phase : { phase: 'loading' };
}

/** Forgets the records completed so far (the tests' pages start afresh). */
export function forgetCompletedRecords() {
  hydrated.clear();
}
