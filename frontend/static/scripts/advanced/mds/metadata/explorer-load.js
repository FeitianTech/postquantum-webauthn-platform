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
    setStatus(forceReload ? 'Refreshing authenticator explorer…' : 'Loading authenticator explorer…', 'info');
    setColumnResizersEnabled(false);

    const hasExplorerSource = Boolean(explorerSource && typeof explorerSource.resolve === 'function');
    const primarySource = hasExplorerSource
        ? explorerSource.resolve({ forceReload })
        : { url: mdsExplorerFullPath, cache: forceReload ? 'reload' : 'no-store', kind: 'api' };

    async function fetchSnapshot(source) {
        const fetchOptions = {
            cache: source.cache,
        };
        if (signal) {
            fetchOptions.signal = signal;
        }

        const response = await fetch(source.url, fetchOptions);
        let payload = null;
        try {
            payload = await response.json();
        } catch {
            payload = null;
        }
        return { response, payload };
    }

    const task = (async () => {
        try {
            let result = null;
            if (primarySource.kind === 'static') {
                // The packaged snapshot is an optimisation; any problem loading
                // it falls back to the per-session API.
                try {
                    result = await fetchSnapshot(primarySource);
                    if (!result.response.ok || !result.payload || typeof result.payload !== 'object') {
                        result = null;
                    }
                } catch (error) {
                    if (error && error.name === 'AbortError') {
                        throw error;
                    }
                    result = null;
                }
                if (!result) {
                    result = await fetchSnapshot(explorerSource.fallback({ forceReload }));
                }
            } else {
                result = await fetchSnapshot(primarySource);
            }

            const { response, payload } = result;

            if (!response.ok) {
                if (response.status === 404) {
                    resetExplorerState(
                        payload && typeof payload.error === 'string' && payload.error
                            ? payload.error
                            : missingMetadataMessage,
                        'info',
                    );
                    return;
                }

                throw new Error(
                    payload && typeof payload.error === 'string' && payload.error
                        ? payload.error
                        : `Explorer request failed with status ${response.status}.`,
                );
            }

            if (!payload || typeof payload !== 'object') {
                throw new Error('Explorer response was not valid JSON.');
            }

            if (hasExplorerSource && typeof explorerSource.noteSnapshotMeta === 'function') {
                explorerSource.noteSnapshotMeta(payload.meta);
            }

            const payloadEntries = Array.isArray(payload.entries) ? payload.entries : [];
            const shouldUseLegacyEntryParser =
                payloadEntries.length > 0
                && payloadEntries.some(entry => {
                    if (!entry || typeof entry !== 'object') {
                        return true;
                    }
                    return !Object.prototype.hasOwnProperty.call(entry, 'entryId');
                });

            if (shouldUseLegacyEntryParser) {
                await applyMetadataEntries(payload, { note, signal });
            } else {
                applyExplorerSnapshot(payload, note);
            }
        } catch (error) {
            if (error && error.name === 'AbortError') {
                throw error;
            }

            console.error('Failed to load FIDO MDS explorer data:', error);
            const message =
                error instanceof Error && error.message
                    ? error.message
                    : 'Unable to load the packaged authenticator explorer.';
            setStatus(message, 'error');
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
