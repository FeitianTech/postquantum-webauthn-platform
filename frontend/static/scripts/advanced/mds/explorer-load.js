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

    const task = (async () => {
        const fetchOptions = {
            cache: forceReload ? 'reload' : 'no-store',
        };
        if (signal) {
            fetchOptions.signal = signal;
        }

        try {
            const response = await fetch(mdsExplorerFullPath, fetchOptions);
            let payload = null;
            try {
                payload = await response.json();
            } catch {
                payload = null;
            }

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
