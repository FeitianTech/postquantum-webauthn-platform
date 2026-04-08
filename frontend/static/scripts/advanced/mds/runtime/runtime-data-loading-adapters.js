import {
    applyMetadataEntriesInState,
    applyMetadataEntriesLazyInState,
    startBackgroundMetadataLoadingInState,
} from '../metadata/metadata-entry-loading.js';
import {
    buildLoadedStatus as buildLoadedStatusFromSnapshot,
    finalizeBackgroundLoading as finalizeBackgroundLoadingState,
    populateCertificateDerivedInfoForBatch as populateCertificateDerivedInfoForBatchEntries,
    populateCertificateDerivedInfoInternal as populateCertificateDerivedInfoForEntries,
    updateBackgroundLoadingStatus as updateBackgroundLoadingStatusForProgress,
} from '../metadata/metadata-derived-info.js';

export function createMdsDataLoadingAdapters(config = {}) {
    const {
        getState,
        getMdsData,
        getHasLoaded,
        setHasLoaded,
        getLazyLoader,
        setLazyLoader,
        getBackgroundLoadingInProgress,
        setBackgroundLoadingInProgress,
        getAbortSignal,
        throwIfAborted,
        loaderIsActive,
        loaderSetPhase,
        loaderSetMetadataCount,
        loaderSetProgress,
        transformEntry,
        transformEntryLightweight,
        createMdsLazyLoader,
        setMdsData,
        setUpdateButtonMode,
        resetSortState,
        normaliseAaguid,
        formatSnapshotTimestamp,
        initialMdsInfo,
        mdsVerifiedMetaPath,
        collectOptionSets,
        updateOptionLists,
        applyFilters,
        scheduleHorizontalScrollMetricsUpdate,
        setStatus,
        setColumnResizersEnabled,
        upgradeEntryToFull,
        normaliseCertificateBase64,
        decodeCertificate,
    } = config;

    const setByAaguid = map => {
        const state = getState();
        if (state) {
            state.byAaguid = map;
        }
    };

    const setDefaultStatus = value => {
        const state = getState();
        if (!state || !value || typeof value !== 'object') {
            return;
        }
        state.defaultStatus = {
            html: typeof value.html === 'string' ? value.html : '',
            variant: typeof value.variant === 'string' ? value.variant : 'info',
            title: typeof value.title === 'string' ? value.title : '',
        };
    };

    const setStatusTitleWithDefault = title => {
        const state = getState();
        if (!state) {
            return;
        }

        if (state.statusEl) {
            if (typeof title === 'string' && title) {
                state.statusEl.setAttribute('title', title);
            } else {
                state.statusEl.removeAttribute('title');
            }
        }

        if (state.defaultStatus) {
            state.defaultStatus.title = typeof title === 'string' ? title : '';
        }
    };

    const setStatusTitleElementOnly = title => {
        const state = getState();
        if (!state?.statusEl) {
            return;
        }

        if (typeof title === 'string' && title) {
            state.statusEl.setAttribute('title', title);
        } else {
            state.statusEl.removeAttribute('title');
        }
    };

    async function applyMetadataEntries(metadata, options = {}) {
        return applyMetadataEntriesInState(metadata, options, {
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
            setStatusTitle: setStatusTitleWithDefault,
            setColumnResizersEnabled,
        });
    }

    async function applyMetadataEntriesLazy(metadata, options = {}) {
        return applyMetadataEntriesLazyInState(metadata, options, {
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
            setStatusTitle: setStatusTitleElementOnly,
            setColumnResizersEnabled,
            startBackgroundMetadataLoading,
        });
    }

    async function startBackgroundMetadataLoading(metadata, options = {}) {
        return startBackgroundMetadataLoadingInState(metadata, options, {
            getLazyLoader,
            getBackgroundLoadingInProgress,
            setBackgroundLoadingInProgress,
            getState,
            updateBackgroundLoadingStatus,
            finalizeBackgroundLoading,
            populateCertificateDerivedInfoForBatch,
            getMdsData,
        });
    }

    function updateBackgroundLoadingStatus(parsed, total, lastUpdatedDate) {
        return updateBackgroundLoadingStatusForProgress(parsed, total, lastUpdatedDate, setStatus);
    }

    async function populateCertificateDerivedInfoInternal(
        entries,
        { upgradeLightweightEntries = false } = {},
    ) {
        return populateCertificateDerivedInfoForEntries(
            entries,
            { upgradeLightweightEntries },
            {
                upgradeEntryToFull,
                normaliseCertificateBase64,
                decodeCertificate,
            },
        );
    }

    async function populateCertificateDerivedInfoForBatch(entries) {
        await populateCertificateDerivedInfoForBatchEntries(entries, {
            upgradeEntryToFull,
            normaliseCertificateBase64,
            decodeCertificate,
        });
    }

    async function finalizeBackgroundLoading(metadata, lastUpdatedDate) {
        finalizeBackgroundLoadingState({
            metadata,
            lastUpdatedDate,
            mdsData: getMdsData(),
            state: getState(),
            setStatus,
        });
    }

    function buildLoadedStatus(snapshot, note) {
        return buildLoadedStatusFromSnapshot(snapshot, note, formatSnapshotTimestamp);
    }

    async function populateCertificateDerivedInfo(entries) {
        await populateCertificateDerivedInfoInternal(entries);
    }

    return {
        applyMetadataEntries,
        applyMetadataEntriesLazy,
        startBackgroundMetadataLoading,
        updateBackgroundLoadingStatus,
        populateCertificateDerivedInfoInternal,
        populateCertificateDerivedInfoForBatch,
        finalizeBackgroundLoading,
        buildLoadedStatus,
        populateCertificateDerivedInfo,
    };
}
