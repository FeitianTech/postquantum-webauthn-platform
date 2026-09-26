import {
    classifyExplorerAnswer,
    explorerLoadFailure,
    needsLegacyEntryParser,
    requestExplorerSnapshot,
} from '../explorer/loading.js';
import { explorerLoadingStatus } from '../explorer/status.js';

export async function loadMdsDataInState(statusNote, options = {}, deps = {}) {
    const {
        getState,
        getAbortSignal,
        throwIfAborted,
        getIsLoading,
        setIsLoading,
        getLoadPromise,
        setLoadPromise,
        getHasLoaded,
        setHasLoaded,
        setExplorerPreloadPromise,
        clearResolvedEntryCache,
        setStatus,
        setRetryButtonVisible,
        setColumnResizersEnabled,
        mdsExplorerFullPath,
        explorerSource,
        missingMetadataMessage,
        resetExplorerState,
        applyMetadataEntries,
        applyExplorerSnapshot,
    } = deps;

    const state = getState();
    if (!state) {
        return;
    }

    const opts = options && typeof options === 'object' ? options : {};
    const signal = getAbortSignal(opts);
    const forceReload = Boolean(opts.forceReload);
    const note = typeof statusNote === 'string' ? statusNote.trim() : '';

    throwIfAborted(signal);

    const activeLoadPromise = getLoadPromise();
    if (getIsLoading() && activeLoadPromise) {
        await activeLoadPromise;
        if (!forceReload) {
            return;
        }
    }

    if (getHasLoaded() && !forceReload) {
        return;
    }

    if (forceReload) {
        setExplorerPreloadPromise(null);
        clearResolvedEntryCache();
    }

    setIsLoading(true);
    setRetryButtonVisible(false);
    setStatus(explorerLoadingStatus(forceReload), 'info');
    setColumnResizersEnabled(false);

    const hasExplorerSource = Boolean(explorerSource && typeof explorerSource.resolve === 'function');

    const task = (async () => {
        try {
            const answer = await requestExplorerSnapshot(explorerSource, {
                forceReload,
                signal,
                apiPath: mdsExplorerFullPath,
            });
            const outcome = classifyExplorerAnswer(answer, missingMetadataMessage);

            if (outcome.kind === 'missing') {
                resetExplorerState(outcome.message, 'info');
                return;
            }
            if (outcome.kind === 'failed') {
                throw new Error(outcome.message);
            }

            const { payload } = outcome;
            if (hasExplorerSource && typeof explorerSource.noteSnapshotMeta === 'function') {
                explorerSource.noteSnapshotMeta(payload.meta);
            }

            if (needsLegacyEntryParser(payload)) {
                await applyMetadataEntries(payload, { note, signal });
            } else {
                applyExplorerSnapshot(payload, note);
            }
        } catch (error) {
            if (error && error.name === 'AbortError') {
                throw error;
            }

            console.error('Failed to load FIDO MDS explorer data:', error);
            setStatus(explorerLoadFailure(error), 'error');
            setRetryButtonVisible(true);

            if (!getHasLoaded()) {
                setHasLoaded(false);
                setColumnResizersEnabled(false);
            } else {
                setColumnResizersEnabled(true);
            }
        } finally {
            setIsLoading(false);
        }
    })();

    setLoadPromise(task);
    setExplorerPreloadPromise(task);

    try {
        await task;
    } finally {
        if (getLoadPromise() === task) {
            setLoadPromise(null);
        }
        if (!getIsLoading()) {
            setExplorerPreloadPromise(null);
        }
    }
}
