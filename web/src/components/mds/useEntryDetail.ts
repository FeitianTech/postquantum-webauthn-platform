import { useCallback, useEffect, useState } from 'react';

import { hasDetail, resolveEntry, resolveQuery } from './entryModel';
import type { MdsEntry } from './model';
import type { ExplorerPhase } from './useMdsExplorer';

/**
 * Where an entry the page shows stands: the list is still loading; the server
 * is being asked for it; it is found; the server has no such entry (its
 * sentence); or asking failed (its sentence, if any), which can be retried.
 */
export type EntryDetail =
  | { phase: 'waiting' }
  | { phase: 'resolving' }
  | { phase: 'found'; entry: MdsEntry }
  | { phase: 'missing'; message: string }
  | { phase: 'failed'; message: string };

type Resolved = { entryId: string; attempt: number; detail: EntryDetail };

// The entry #mds/<entryId> names, with all it shows. The list holds every
// entry with its detail inline, so it is shown from there once the list has
// loaded; an entry the list does not hold (a link to another session's upload,
// an entry gone since) is asked of GET /api/mds/metadata/resolve, as the
// current page asks for an entry without its detail.
export function useEntryDetail(entryId: string, entries: MdsEntry[], phase: ExplorerPhase) {
  const [resolved, setResolved] = useState<Resolved | null>(null);
  const [attempt, setAttempt] = useState(0);

  const listed = entryId ? entries.find((entry) => entry.entryId === entryId) : undefined;
  const fromList = listed && hasDetail(listed) ? listed : null;
  const listLoading = phase === 'idle' || phase === 'loading';
  const mustAsk = Boolean(entryId) && !fromList && (Boolean(listed) || !listLoading);

  useEffect(() => {
    if (!mustAsk) return undefined;
    const controller = new AbortController();
    const settle = (detail: EntryDetail) => {
      if (!controller.signal.aborted) setResolved({ entryId, attempt, detail });
    };
    resolveEntry(listed ? resolveQuery(listed) : { entryId }, { signal: controller.signal })
      .then(({ entry, failure }) => {
        if (entry) settle({ phase: 'found', entry });
        else if (failure && failure.status !== 404) settle({ phase: 'failed', message: failure.message });
        else settle({ phase: 'missing', message: failure?.message ?? '' });
      })
      .catch((error: unknown) => {
        settle({ phase: 'failed', message: error instanceof Error ? error.message : '' });
      });
    return () => controller.abort();
    // `listed` gives the query only when asking starts; a new list does not ask again.
  }, [entryId, mustAsk, attempt]);

  const retry = useCallback(() => setAttempt((value) => value + 1), []);

  let detail: EntryDetail;
  if (fromList) detail = { phase: 'found', entry: fromList };
  else if (!mustAsk) detail = { phase: 'waiting' };
  else if (resolved && resolved.entryId === entryId && resolved.attempt === attempt) detail = resolved.detail;
  else detail = { phase: 'resolving' };

  return { detail, retry };
}
