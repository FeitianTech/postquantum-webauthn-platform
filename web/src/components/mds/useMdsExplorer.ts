import {
  type ExplorerSource,
  classifyExplorerParts,
  createExplorerSource,
  explorerLoadFailure,
  requestExplorerParts,
} from '@/logic/mds/explorer-source.js';
import {
  type MdsEntry,
  type MdsSnapshot,
  fetchExplorerInfo,
  isMissingSnapshot,
  prepareSnapshotEntries,
} from '@/logic/mds/explorer/loading.js';
import {
  EXPLORER_REFRESHED_NOTE,
  type ExplorerStatus,
  explorerLoadedStatus,
  explorerLoadingStatus,
  formatInitialExplorerStatus,
  normaliseSnapshotInfo,
} from '@/logic/mds/explorer/status.js';
import { CUSTOM_METADATA_UPDATED_NOTE, mergeCustomEntries } from '@/logic/mds/explorer/custom-metadata.js';
import { useCallback, useEffect, useRef, useState } from 'react';

export type ExplorerPhase = 'idle' | 'loading' | 'loaded' | 'failed';

export type Explorer = {
  phase: ExplorerPhase;
  entries: MdsEntry[];
  status: ExplorerStatus;
  /** No snapshot on the server and nothing uploaded: the list has nothing to show. */
  missing: boolean;
  /** Counts the snapshots shown, so the view resets its sort for each. */
  version: number;
  retry: () => void;
  /** An upload or delete answered with the session's entries: show them with the packaged list. */
  applyCustomEntries: (custom: MdsSnapshot) => void;
  /** An upload or delete answered without them: load both parts again. */
  reload: () => Promise<void>;
};

// The explorer's data, in explorer-source.js's order: what the page starts from
// (GET /api/mds/metadata/info), then the packaged list and, while the session has
// uploads, its own entries, merged; and the status line's sentences along the way.
// It starts the first time the section is shown. Retry asks both parts again.
export function useMdsExplorer(active: boolean): Explorer {
  const [phase, setPhase] = useState<ExplorerPhase>('idle');
  const [entries, setEntries] = useState<MdsEntry[]>([]);
  const [status, setStatus] = useState<ExplorerStatus>({ text: formatInitialExplorerStatus(null), variant: 'info', title: '' });
  const [isMissing, setMissing] = useState(false);
  const [version, setVersion] = useState(0);
  // Until the page knows what to start from, the session may have uploads.
  const source = useRef<ExplorerSource>(createExplorerSource(null));
  const started = useRef(false);
  // Counts loads, so an answer overtaken by a later load is dropped.
  const generation = useRef(0);
  // The packaged list last loaded (null: the server has none), which an upload's
  // or a delete's answer is merged with; undefined until a load has ended well.
  const packaged = useRef<MdsSnapshot | null | undefined>(undefined);

  const show = useCallback((snapshot: MdsSnapshot, note: string) => {
    source.current.noteSnapshotMeta(snapshot.meta);
    const shown = prepareSnapshotEntries(snapshot);
    setEntries(shown);
    setMissing(isMissingSnapshot(snapshot));
    setStatus(explorerLoadedStatus(snapshot, note, shown.length));
    setVersion((value) => value + 1);
    setPhase('loaded');
  }, []);

  const load = useCallback(
    async (note: string, forceReload: boolean) => {
      const current = ++generation.current;
      setPhase('loading');
      setStatus({ text: explorerLoadingStatus(forceReload), variant: 'info', title: '' });
      try {
        const outcome = classifyExplorerParts(await requestExplorerParts(source.current, { forceReload }));
        if (current !== generation.current) return;
        if (outcome.kind === 'failed') throw new Error(outcome.message);
        packaged.current = outcome.packaged;
        show(mergeCustomEntries(outcome.packaged, outcome.custom), note);
      } catch (error) {
        if (current !== generation.current) return;
        setStatus({ text: explorerLoadFailure(error), variant: 'error', title: '' });
        setPhase('failed');
      }
    },
    [show],
  );

  useEffect(() => {
    if (!active || started.current) return;
    started.current = true;
    void (async () => {
      const info = await fetchExplorerInfo();
      source.current = createExplorerSource(info);
      setStatus({ text: formatInitialExplorerStatus(normaliseSnapshotInfo(info)), variant: 'info', title: '' });
      await load('', false);
    })();
  }, [active, load]);

  const retry = useCallback(() => {
    void load(EXPLORER_REFRESHED_NOTE, true);
  }, [load]);

  const reload = useCallback(() => load(CUSTOM_METADATA_UPDATED_NOTE, true), [load]);

  const applyCustomEntries = useCallback(
    (custom: MdsSnapshot) => {
      // No packaged list to merge with yet (the first load is still out, or failed):
      // load both again, the session's part as it is now.
      if (packaged.current === undefined) {
        void reload();
        return;
      }
      // Newer than any load still out: that load's answer is dropped.
      generation.current += 1;
      show(mergeCustomEntries(packaged.current, custom), CUSTOM_METADATA_UPDATED_NOTE);
    },
    [reload, show],
  );

  return { phase, entries, status, missing: isMissing, version, retry, applyCustomEntries, reload };
}
