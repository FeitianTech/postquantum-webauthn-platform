import { startBackgroundMetadataLoadingInState as startBackgroundMetadataLoadingFromModule } from './metadata-background-loading.js';
import { applyMetadataEntriesLazyInState as applyMetadataEntriesLazyFromModule } from './metadata-entry-lazy.js';

export async function applyMetadataEntriesInState(metadata, options = {}, deps = {}) {
    const {
        getState,
        getAbortSignal,
        throwIfAborted,
        loaderIsActive,
        getHasLoaded,
        loaderSetPhase,
        loaderSetMetadataCount,
        loaderSetProgress,
        applyMetadataEntriesLazy,
        transformEntry,
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
        populateCertificateDerivedInfo,
        applyFilters,
        scheduleHorizontalScrollMetricsUpdate,
        setHasLoaded,
        setStatus,
        setDefaultStatus,
        setStatusTitle,
        setColumnResizersEnabled,
    } = deps;

    const opts = options && typeof options === 'object' ? options : {};
    const noteText = typeof opts.note === 'string' ? opts.note : '';
    const signal = getAbortSignal(opts);
    const useLazyLoading = opts.useLazyLoading ?? true;

    throwIfAborted(signal);

    if (!getState()) {
        return;
    }

    const rawEntries = Array.isArray(metadata?.entries) ? metadata.entries : [];
    const totalEntries = rawEntries.length;
    const shouldReportProgress = loaderIsActive() && !getHasLoaded();

    throwIfAborted(signal);

    if (useLazyLoading && totalEntries > 100) {
        await applyMetadataEntriesLazy(metadata, { ...opts, shouldReportProgress, noteText, signal });
        return;
    }

    const entries = [];

    if (shouldReportProgress) {
        const initialProgress = totalEntries ? 58 : 72;
        loaderSetPhase('Processing authenticator metadata…', { progress: initialProgress });
        loaderSetMetadataCount(0);
    }

    if (totalEntries) {
        const progressBase = 58;
        const progressRange = 32;
        let processedCount = 0;

        rawEntries.forEach((entry, index) => {
            throwIfAborted(signal);
            processedCount += 1;
            const transformed = transformEntry(entry, index);
            if (transformed) {
                entries.push(transformed);
                if (shouldReportProgress) {
                    loaderSetMetadataCount(entries.length);
                }
            }

            if (shouldReportProgress) {
                const ratio = processedCount / totalEntries;
                const progress = progressBase + Math.min(progressRange, ratio * progressRange);
                loaderSetProgress(progress);
            }
        });
    } else if (shouldReportProgress) {
        loaderSetProgress(88);
    }

    setMdsData(entries);
    setUpdateButtonMode('update');
    resetSortState();

    throwIfAborted(signal);

    const map = new Map();
    entries.forEach(item => {
        throwIfAborted(signal);
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

    const optionSets = collectOptionSets(entries);
    updateOptionLists(optionSets);

    try {
        throwIfAborted(signal);
        await populateCertificateDerivedInfo(entries);
    } catch (error) {
        console.error('Failed to derive attestation certificate details:', error);
    }

    throwIfAborted(signal);

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

    const statusMessage = statusParts.join(' ');
    setStatus(statusMessage, 'success');

    setDefaultStatus({
        html: statusMessage,
        variant: 'success',
        title: typeof metadata?.legalHeader === 'string' ? metadata.legalHeader : '',
    });

    if (metadata?.legalHeader) {
        setStatusTitle(metadata.legalHeader);
    } else {
        setStatusTitle('');
    }

    setColumnResizersEnabled(true);

    if (shouldReportProgress) {
        loaderSetMetadataCount(entries.length);
        loaderSetPhase('Finalising interface…', { progress: 94 });
    }
}

export async function applyMetadataEntriesLazyInState(metadata, options = {}, deps = {}) {
    return applyMetadataEntriesLazyFromModule(metadata, options, deps);
}

export async function startBackgroundMetadataLoadingInState(metadata, options = {}, deps = {}) {
    return startBackgroundMetadataLoadingFromModule(metadata, options, deps);
}
