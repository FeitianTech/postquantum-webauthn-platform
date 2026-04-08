import { FILTER_LOOKUP, UPDATE_BUTTON_STATES } from './mds-constants.js';
import { formatEnum, normaliseAaguid, normaliseEnumKey, transformEntry, upgradeEntryToFull } from './mds-utils.js';
import {
    setStatus as setStatusInState,
    setUpdateButtonBusy as setUpdateButtonBusyInState,
    setUpdateButtonMode as setUpdateButtonModeInState,
    updateCount as updateCountInState,
    updateOptionLists as updateOptionListsInState,
} from './mds/status-controls.js';
import { normaliseCertificateBase64 as normaliseCertificateBase64Value } from './mds/certificate-utils.js';
import { runWithMetadataUpdateOverlayInState, showMetadataUpdateOverlayInState } from './mds/update-overlay.js';
import { decodeCertificateWithState } from './mds/certificate-decode.js';
import { refreshMetadataInState } from './mds/runtime-refresh-metadata.js';
import { createCustomMetadataRuntime } from './mds/runtime-custom-metadata-runtime.js';
import { createScrollControllers } from './mds/runtime-scroll-controllers.js';
import { setupMdsRuntimeOrchestration } from './mds/runtime-orchestration.js';
import {
    formatInitialExplorerStatus as formatInitialExplorerStatusValue,
} from './mds/metadata-helpers.js';
import { setButtonBusy as setButtonBusyValue, throwIfAborted as throwIfAbortedValue } from './mds/custom-panel-utils.js';
import { createDetailStickyHeader } from './mds/detail-sticky-header.js';

let mdsState = null;
let mdsData = [];
let filteredData = [];
let isLoading = false;
let hasLoaded = false;
let isUpdatingMetadata = false;
let loadPromise = null;
const certificateCache = new Map();
let initialMdsInfo = null;
let initialMdsSnapshot = null;
let explorerPreloadPromise = null;
const resolvedEntryCache = new Map();
let lazyLoader = null;
let backgroundLoadingInProgress = false;

const getState = () => mdsState;
const setState = value => { mdsState = value; };
const getMdsData = () => mdsData;
const setMdsData = value => { mdsData = Array.isArray(value) ? value : []; };
const getFilteredData = () => filteredData;
const setFilteredData = value => { filteredData = Array.isArray(value) ? value : []; };
const getHasLoaded = () => hasLoaded;
const setHasLoaded = value => { hasLoaded = Boolean(value); };
const getIsLoading = () => isLoading;
const setIsLoading = value => { isLoading = Boolean(value); };
const getLoadPromise = () => loadPromise;
const setLoadPromise = value => { loadPromise = value; };
const setExplorerPreloadPromise = value => { explorerPreloadPromise = value; };
const clearResolvedEntryCache = () => { resolvedEntryCache.clear(); };
const getResolvedEntryCache = () => resolvedEntryCache;
const getLazyLoader = () => lazyLoader;
const setLazyLoader = value => { lazyLoader = value; };
const getBackgroundLoadingInProgress = () => backgroundLoadingInProgress;
const setBackgroundLoadingInProgress = value => { backgroundLoadingInProgress = Boolean(value); };

function getInitialSnapshotPayload() {
    if (!initialMdsSnapshot || typeof initialMdsSnapshot !== 'object') {
        return null;
    }
    if (!Array.isArray(initialMdsSnapshot.entries)) {
        return null;
    }
    if (!initialMdsSnapshot.meta || typeof initialMdsSnapshot.meta !== 'object') {
        return null;
    }
    const snapshot = initialMdsSnapshot;
    initialMdsSnapshot = null;
    return snapshot;
}

function setRetryButtonVisible(visible) {
    const button = mdsState?.retryButton;
    if (!(button instanceof HTMLButtonElement)) {
        return;
    }

    button.hidden = !visible;
    button.setAttribute('aria-hidden', visible ? 'false' : 'true');
}

const DEFAULT_MIN_COLUMN_WIDTH = 64;
const FLOATING_SCROLL_BOTTOM_MARGIN = 24;
const FLOATING_SCROLL_SIDE_MARGIN = 16;
const {
    hideHorizontalScroll,
    syncHorizontalScrollPositions,
    waitForLayoutSettled,
    waitForStateReady,
    waitForRowByKey,
    scrollRowIntoView,
    setHighlightedRow,
    hideScrollTopButton,
    scrollMdsSectionToTop,
    handleWindowScroll,
    scheduleScrollTopButtonUpdate,
    scheduleColumnResizerMetricsUpdate,
    scheduleRowHeightLock,
    scheduleHorizontalScrollMetricsUpdate,
    columnResizerController,
    sortFilterController,
} = createScrollControllers({
    getState,
    findRowByKey: key => findRowByKey(key),
    isLoading: getIsLoading,
    hasLoaded: getHasLoaded,
    getAllData: getMdsData,
    getFilteredData,
    setFilteredData,
    renderTable: (entries, options) => renderTable(entries, options),
    updateCount: (filtered, total) => updateCount(filtered, total),
    normaliseEnumKey,
    defaultMinColumnWidth: DEFAULT_MIN_COLUMN_WIDTH,
    floatingScrollSideMargin: FLOATING_SCROLL_SIDE_MARGIN,
    floatingScrollBottomMargin: FLOATING_SCROLL_BOTTOM_MARGIN,
});

let customMetadataItems = [];

async function runWithMetadataUpdateOverlay(task, options = {}) {
    return runWithMetadataUpdateOverlayInState(mdsState, task, options, {
        throwIfAborted: throwIfAbortedValue,
        showMetadataUpdateOverlay: (message, overlayOptions = {}) =>
            showMetadataUpdateOverlayInState(mdsState, message, overlayOptions),
    });
}

const {
    setCustomMetadataMessage,
    updateCustomMetadataList,
    handleCustomPanelKeydown,
    openCustomMetadataPanel,
    closeCustomMetadataPanel,
    handleCustomDropzoneDragEnter,
    handleCustomDropzoneDragLeave,
    handleCustomDrop,
    handleCustomFileInputChange,
    deleteCustomMetadata,
} = createCustomMetadataRuntime({
    getState,
    runWithMetadataUpdateOverlay,
    applyExplorerSnapshot: (...args) => applyExplorerSnapshot(...args),
    loadMdsData: (...args) => loadMdsData(...args),
    setButtonBusy: setButtonBusyValue,
    resetCustomMetadataCache: () => {},
});

if (typeof window !== 'undefined') {
    if (window.__INITIAL_MDS_INFO__ && typeof window.__INITIAL_MDS_INFO__ === 'object') {
        initialMdsInfo = window.__INITIAL_MDS_INFO__;
    }
    if (window.__INITIAL_MDS_SNAPSHOT__ && typeof window.__INITIAL_MDS_SNAPSHOT__ === 'object') {
        initialMdsSnapshot = window.__INITIAL_MDS_SNAPSHOT__;
    }
    try {
        delete window.__INITIAL_MDS_INFO__;
    } catch (error) {
        window.__INITIAL_MDS_INFO__ = undefined;
    }
    try {
        delete window.__INITIAL_MDS_SNAPSHOT__;
    } catch (error) {
        window.__INITIAL_MDS_SNAPSHOT__ = undefined;
    }
}

function clearMetadataCache() {
    resolvedEntryCache.clear();
    explorerPreloadPromise = null;
}
const {
    applyExplorerSnapshot,
    loadMdsData,
    waitForMetadataLoad: waitForMetadataLoadInternal,
    renderTable,
    findRowByKey,
} = setupMdsRuntimeOrchestration({
    getState, setState, getMdsData, setMdsData, setFilteredData, getHasLoaded, setHasLoaded,
    getIsLoading, setIsLoading, getLoadPromise, setLoadPromise, setExplorerPreloadPromise,
    clearResolvedEntryCache, getResolvedEntryCache, getLazyLoader, setLazyLoader,
    getBackgroundLoadingInProgress, setBackgroundLoadingInProgress,
    initialMdsInfo, customMetadataItems,
    applyFilters, handleCustomPanelKeydown, closeCustomMetadataPanel, openCustomMetadataPanel,
    handleCustomDropzoneDragEnter, handleCustomDropzoneDragLeave, handleCustomDrop, handleCustomFileInputChange,
    scheduleScrollTopButtonUpdate, syncHorizontalScrollPositions, handleSortButtonClick, scrollMdsSectionToTop,
    refreshMetadata, hideHorizontalScroll, handleWindowScroll, createDetailStickyHeader,
    updateCustomMetadataList, setCustomMetadataMessage, setupColumnResizers, setColumnResizersEnabled, deleteCustomMetadata,
    setUpdateButtonMode, resetSortState, updateOptionLists, scheduleHorizontalScrollMetricsUpdate,
    setStatus, setRetryButtonVisible, updateCount, waitForStateReady, normaliseCertificateBase64, decodeCertificate,
    hideScrollTopButton, scrollRowIntoView, setHighlightedRow, stabiliseColumnWidths,
    scheduleColumnResizerMetricsUpdate, scheduleRowHeightLock,
    isLoading: getIsLoading, loadPromise: getLoadPromise,
    resetFilters, waitForLayoutSettled, waitForRowByKey, updateSortButtonState,
    formatInitialExplorerStatus: formatInitialExplorerStatusValue, getInitialSnapshotPayload,
});

export async function waitForMetadataLoad() {
    return waitForMetadataLoadInternal();
}

function applyFilters(options = {}) {
    return sortFilterController.applyFilters(options);
}

function updateSortButtonState() {
    return sortFilterController.updateSortButtonState();
}

function resetSortState() {
    return sortFilterController.resetSortState();
}

function handleSortButtonClick(sortKey) {
    return sortFilterController.handleSortButtonClick(sortKey);
}

function resetFilters() {
    return sortFilterController.resetFilters();
}

function normaliseCertificateBase64(value) {
    return normaliseCertificateBase64Value(value);
}

async function decodeCertificate(certificateBase64) {
    return decodeCertificateWithState(certificateBase64, {
        normaliseCertificateBase64,
        certificateCache,
        lazyLoader,
        mdsData,
        mdsState,
        normaliseAaguid,
        upgradeEntryToFull,
        transformEntry,
    });
}

function stabiliseColumnWidths() {
    return columnResizerController.stabiliseColumnWidths();
}

function setColumnResizersEnabled(enabled, state = mdsState) {
    return columnResizerController.setColumnResizersEnabled(enabled, state);
}

function setupColumnResizers(state = mdsState) {
    return columnResizerController.setupColumnResizers(state);
}

function updateCount(filtered, total) {
    return updateCountInState(mdsState, filtered, total);
}

function setStatus(message, variant, options = {}) {
    return setStatusInState(mdsState, message, variant, options);
}

function setUpdateButtonBusy(isBusy) {
    return setUpdateButtonBusyInState(mdsState, isBusy, UPDATE_BUTTON_STATES);
}

function setUpdateButtonMode(mode) {
    return setUpdateButtonModeInState(mdsState, mode, UPDATE_BUTTON_STATES);
}

async function refreshMetadata() {
    return refreshMetadataInState({
        getIsUpdating: () => isUpdatingMetadata,
        setIsUpdating: value => {
            isUpdatingMetadata = Boolean(value);
        },
        getIsLoading,
        setStatus,
        setUpdateButtonBusy,
        getState,
        clearMetadataCache,
        loadMdsData,
        setRetryButtonVisible,
    });
}

function updateOptionLists(optionSets) {
    return updateOptionListsInState(mdsState, optionSets, FILTER_LOOKUP, formatEnum);
}
