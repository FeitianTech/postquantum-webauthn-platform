import {
    applyExplorerSnapshotInState,
    integrateResolvedEntryInState,
    loadMdsDataInState,
    resetExplorerStateInState,
    resolveMetadataEntryInState,
} from './explorer-state-loader.js';

export function createMdsDataExplorerAdapters(config = {}) {
    const {
        getState,
        getMdsData,
        setMdsData,
        setFilteredData,
        getHasLoaded,
        setHasLoaded,
        getIsLoading,
        setIsLoading,
        getLoadPromise,
        setLoadPromise,
        setExplorerPreloadPromise,
        clearResolvedEntryCache,
        getResolvedEntryCache,
        getAbortSignal,
        throwIfAborted,
        normaliseAaguid,
        normaliseSnapshotInfo,
        cloneMetadataEntry,
        hasInlineDetail,
        setUpdateButtonMode,
        resetSortState,
        collectOptionSets,
        updateOptionLists,
        applyFilters,
        scheduleHorizontalScrollMetricsUpdate,
        setStatus,
        setRetryButtonVisible,
        setColumnResizersEnabled,
        updateCount,
        columnCount,
        mdsResolvePath,
        mdsExplorerFullPath,
        missingMetadataMessage,
        waitForStateReady,
        applyMetadataEntries,
        buildLoadedStatus,
    } = config;

    function resetExplorerState(message, variant = 'info') {
        return resetExplorerStateInState(message, variant, {
            getState,
            setMdsData,
            setFilteredData,
            setHasLoaded,
            clearResolvedEntryCache,
            updateCount,
            setColumnResizersEnabled,
            setStatus,
            setRetryButtonVisible,
            COLUMN_COUNT: columnCount,
        });
    }

    function applyExplorerSnapshot(snapshot, note = '') {
        return applyExplorerSnapshotInState(snapshot, note, {
            getState,
            normaliseSnapshotInfo,
            cloneMetadataEntry,
            hasInlineDetail,
            getResolvedEntryCache,
            setMdsData,
            resetSortState,
            setUpdateButtonMode,
            normaliseAaguid,
            collectOptionSets,
            updateOptionLists,
            applyFilters,
            scheduleHorizontalScrollMetricsUpdate,
            setColumnResizersEnabled,
            setRetryButtonVisible,
            setHasLoaded,
            buildLoadedStatus,
            setStatus,
        });
    }

    function integrateResolvedEntry(entry) {
        return integrateResolvedEntryInState(entry, {
            getState,
            normaliseAaguid,
            getMdsData,
            setMdsData,
            getHasLoaded,
            applyFilters,
            hasInlineDetail,
            getResolvedEntryCache,
        });
    }

    async function resolveMetadataEntry(query) {
        return resolveMetadataEntryInState(query, {
            mdsResolvePath,
            integrateResolvedEntry,
        });
    }

    async function loadMdsData(statusNote, options = {}) {
        return loadMdsDataInState(statusNote, options, {
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
        });
    }

    async function waitForMetadataLoad() {
        const ready = await waitForStateReady();
        if (!ready || !getState()) {
            return false;
        }
        if (getHasLoaded() && !getIsLoading()) {
            return true;
        }

        const pendingLoad = getLoadPromise();
        if (getIsLoading() && pendingLoad) {
            await pendingLoad;
            return getHasLoaded();
        }

        await loadMdsData();
        return getHasLoaded();
    }

    function getMdsLoadStateSnapshot() {
        return {
            hasLoaded: getHasLoaded(),
            isLoading: getIsLoading(),
        };
    }

    return {
        resetExplorerState,
        applyExplorerSnapshot,
        integrateResolvedEntry,
        resolveMetadataEntry,
        loadMdsData,
        waitForMetadataLoad,
        getMdsLoadStateSnapshot,
    };
}
