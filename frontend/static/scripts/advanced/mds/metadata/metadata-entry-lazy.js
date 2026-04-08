export async function applyMetadataEntriesLazyInState(metadata, options = {}, deps = {}) {
    const {
        getState,
        throwIfAborted,
        getLazyLoader,
        setLazyLoader,
        createMdsLazyLoader,
        loaderSetPhase,
        loaderSetMetadataCount,
        loaderSetProgress,
        transformEntryLightweight,
        setMdsData,
        setUpdateButtonMode,
        resetSortState,
        normaliseAaguid,
        setByAaguid,
        formatSnapshotTimestamp,
        initialMdsInfo,
        mdsVerifiedMetaPath,
        collectOptionSets,
        updateOptionLists,
        applyFilters,
        scheduleHorizontalScrollMetricsUpdate,
        setHasLoaded,
        setStatus,
        setDefaultStatus,
        setStatusTitle,
        setColumnResizersEnabled,
        startBackgroundMetadataLoading,
    } = deps;

    const { shouldReportProgress, noteText, signal } = options;

    throwIfAborted(signal);

    if (!getState()) {
        return;
    }

    if (!getLazyLoader()) {
        setLazyLoader(createMdsLazyLoader());
    }
    const lazyLoader = getLazyLoader();
    lazyLoader.initialize(metadata);

    if (shouldReportProgress) {
        loaderSetPhase('Loading authenticators with optimized parsing…', { progress: 58 });
        loaderSetMetadataCount(0);
    }

    const allRawEntries = lazyLoader.getAllRawEntries();
    const totalEntries = allRawEntries.length;
    const entries = [];

    throwIfAborted(signal);

    const progressBase = 58;
    const progressRange = 32;
    let processedCount = 0;
    const reportInterval = 100;

    allRawEntries.forEach((entry, index) => {
        throwIfAborted(signal);
        processedCount += 1;

        const transformed = transformEntryLightweight(entry, index);
        if (transformed) {
            entries.push(transformed);
        }

        if (shouldReportProgress && processedCount % reportInterval === 0) {
            loaderSetMetadataCount(entries.length);
            const ratio = processedCount / totalEntries;
            const progress = progressBase + Math.min(progressRange, ratio * progressRange);
            loaderSetProgress(progress);
        }
    });

    if (shouldReportProgress) {
        loaderSetMetadataCount(entries.length);
        loaderSetProgress(90);
    }

    setMdsData(entries);
    setUpdateButtonMode('update');
    resetSortState();

    throwIfAborted(signal);

    const map = new Map();
    entries.forEach(item => {
        const key = normaliseAaguid(item.aaguid || item.id);
        if (key) {
            map.set(key, item);
        }
    });
    setByAaguid(map);

    let lastUpdatedDate =
        formatSnapshotTimestamp(metadata?.meta || metadata)
        || formatSnapshotTimestamp(initialMdsInfo)
        || '';

    if (!lastUpdatedDate) {
        try {
            const metaResponse = await fetch(mdsVerifiedMetaPath, { cache: 'no-store' });
            if (metaResponse.ok) {
                const metaData = await metaResponse.json();
                lastUpdatedDate = formatSnapshotTimestamp(metaData) || '';
            }
        } catch {
            lastUpdatedDate = '';
        }
    }

    updateOptionLists(collectOptionSets(entries));

    applyFilters();
    scheduleHorizontalScrollMetricsUpdate();

    setHasLoaded(true);

    const statusParts = [`Loaded ${entries.length.toLocaleString()} authenticators.`];
    if (lastUpdatedDate) {
        statusParts.push(`Last updated: ${lastUpdatedDate}.`);
    }
    if (noteText) {
        statusParts.push(noteText);
    }
    statusParts.push('Processing full details in background…');

    const statusMessage = statusParts.join(' ');
    setStatus(statusMessage, 'info');
    setDefaultStatus({ html: statusMessage, variant: 'info', title: '' });

    if (metadata?.legalHeader) {
        setStatusTitle(metadata.legalHeader);
    }

    setColumnResizersEnabled(true);

    if (shouldReportProgress) {
        loaderSetMetadataCount(entries.length);
        loaderSetPhase('Finalising interface…', { progress: 94 });
    }

    startBackgroundMetadataLoading(metadata, { signal, lastUpdatedDate }).catch(error => {
        console.error('Background metadata loading failed:', error);
        const state = getState();
        if (state?.statusEl && !state.statusEl.hidden) {
            const currentStatus = state.statusEl.textContent || '';
            if (currentStatus.includes('Processing full details')) {
                setStatus(
                    `${currentStatus.split('Processing')[0]} Background processing encountered an error.`,
                    'warning',
                );
            }
        }
    });
}
