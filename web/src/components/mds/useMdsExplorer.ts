import { explorerLoadFailure, isMissingSnapshot } from '@/logic/advanced/mds/explorer/loading.js';
import { EXPLORER_REFRESHED_NOTE, explorerLoadingStatus } from '@/logic/advanced/mds/explorer/status.js';
import { CUSTOM_METADATA_UPDATED_NOTE } from '@/logic/advanced/mds/explorer/custom-metadata.js';
import { formatInitialExplorerStatus, normaliseSnapshotInfo } from '@/logic/advanced/mds/metadata/metadata-helpers.js';
import { useCallback, useEffect, useRef, useState } from 'react';

import {
  type ExplorerSource,
  type ExplorerStatus,
  type MdsEntry,
  type MdsSnapshot,
  askExplorerInfo,
  askExplorerSnapshot,
  loadedStatus,
  makeExplorerSource,
  readExplorerAnswer,
  snapshotEntries,
} from './model';

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
  /** An upload or delete answered with the session's snapshot: show it. */
  applySnapshot: (snapshot: MdsSnapshot) => void;
  /** An upload or delete answered without one: load the session's list again. */
  reload: () => Promise<void>;
};

const initialSentence = formatInitialExplorerStatus as (info: unknown) => string;
const snapshotInfo = normaliseSnapshotInfo as (info: unknown) => unknown;
const loadFailure = explorerLoadFailure as (error: unknown) => string;
const loadingSentence = explorerLoadingStatus as (forceReload: boolean) => string;
const missing = isMissingSnapshot as (snapshot: MdsSnapshot) => boolean;

// The explorer's data, in explorer/loading.js's order: what the page starts
// from (GET /api/mds/metadata/info), then the snapshot, from the packaged file while the
// session has uploaded nothing and from the session's own list otherwise, and
// the status line's sentences along the way. It starts the first time the
// section is shown. Retry asks the session's list again.
export function useMdsExplorer(active: boolean): Explorer {
  const [phase, setPhase] = useState<ExplorerPhase>('idle');
  const [entries, setEntries] = useState<MdsEntry[]>([]);
  const [status, setStatus] = useState<ExplorerStatus>({ text: initialSentence(null), variant: 'info', title: '' });
  const [isMissing, setMissing] = useState(false);
  const [version, setVersion] = useState(0);
  const source = useRef<ExplorerSource | null>(null);
  const started = useRef(false);
  // Counts loads, so an answer overtaken by a later load is dropped.
  const generation = useRef(0);

  const show = useCallback((snapshot: MdsSnapshot, note: string) => {
    source.current?.noteSnapshotMeta(snapshot.meta);
    const shown = snapshotEntries(snapshot);
    setEntries(shown);
    setMissing(missing(snapshot));
    setStatus(loadedStatus(snapshot, note, shown.length));
    setVersion((value) => value + 1);
    setPhase('loaded');
  }, []);

  const load = useCallback(
    async (note: string, forceReload: boolean) => {
      const current = ++generation.current;
      setPhase('loading');
      setStatus({ text: loadingSentence(forceReload), variant: 'info', title: '' });
      try {
        const outcome = readExplorerAnswer(await askExplorerSnapshot(source.current, { forceReload }));
        if (current !== generation.current) return;
        if (outcome.kind === 'failed') throw new Error(outcome.message);
        if (outcome.kind === 'missing') {
          show({ entries: [] }, '');
          setStatus({ text: outcome.message, variant: 'info', title: '' });
          return;
        }
        show(outcome.payload, note);
      } catch (error) {
        if (current !== generation.current) return;
        setStatus({ text: loadFailure(error), variant: 'error', title: '' });
        setPhase('failed');
      }
    },
    [show],
  );

  useEffect(() => {
    if (!active || started.current) return;
    started.current = true;
    void (async () => {
      const info = await askExplorerInfo();
      source.current = makeExplorerSource(info);
      setStatus({ text: initialSentence(snapshotInfo(info)), variant: 'info', title: '' });
      await load('', false);
    })();
  }, [active, load]);

  const retry = useCallback(() => {
    void load(EXPLORER_REFRESHED_NOTE, true);
  }, [load]);

  const applySnapshot = useCallback(
    (snapshot: MdsSnapshot) => {
      // Newer than any load still out: that load's answer is dropped.
      generation.current += 1;
      show(snapshot, CUSTOM_METADATA_UPDATED_NOTE);
    },
    [show],
  );
  const reload = useCallback(() => load(CUSTOM_METADATA_UPDATED_NOTE, true), [load]);

  return { phase, entries, status, missing: isMissing, version, retry, applySnapshot, reload };
}
