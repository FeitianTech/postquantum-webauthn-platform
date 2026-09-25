import { readPageData } from '../../shared/utils/page-data.js';
import { FILTER_LOOKUP, UPDATE_BUTTON_STATES } from './constants.js';
import { formatEnum, normaliseAaguid, normaliseEnumKey, transformEntry, upgradeEntryToFull } from './utils.js';
import {
    setStatus as setStatusInState,
    setUpdateButtonBusy as setUpdateButtonBusyInState,
    setUpdateButtonMode as setUpdateButtonModeInState,
    updateCount as updateCountInState,
    updateOptionLists as updateOptionListsInState,
} from './status-controls.js';
import { normaliseCertificateBase64 as normaliseCertificateBase64Value } from './certificate-utils.js';
import { runWithMetadataUpdateOverlayInState, showMetadataUpdateOverlayInState } from './custom/update-overlay.js';
import { decodeCertificateWithState } from './metadata/certificate-decode.js';
import { refreshMetadataInState } from './runtime/runtime-refresh-metadata.js';
import { createCustomMetadataRuntime } from './runtime/runtime-custom-metadata-runtime.js';
import { createScrollControllers } from './runtime/runtime-scroll-controllers.js';
import { setupMdsRuntimeOrchestration } from './runtime/runtime-orchestration.js';
import {
    formatInitialExplorerStatus as formatInitialExplorerStatusValue,
} from './metadata/metadata-helpers.js';
import { setButtonBusy as setButtonBusyValue, throwIfAborted as throwIfAbortedValue } from './custom/custom-panel-utils.js';
import { createDetailStickyHeader } from './detail-sticky-header.js';

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

// The packaged snapshot's summary, from the page (index.html). A whole snapshot
// can be given the same way; the server renders none, the tests do.
const pageMdsInfo = readPageData('initial-mds-info');
if (pageMdsInfo && typeof pageMdsInfo === 'object') {
    initialMdsInfo = pageMdsInfo;
}
const pageMdsSnapshot = readPageData('initial-mds-snapshot');
if (pageMdsSnapshot && typeof pageMdsSnapshot === 'object') {
    initialMdsSnapshot = pageMdsSnapshot;
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
    highlightAuthenticatorRowByAaguid,
    finaliseHighlightedAuthenticatorRow,
    resolveEntryByAaguid,
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

// What the credential detail view uses to show an authenticator in the explorer;
// main.js hands them to advanced/credentials (setMdsNavigation).
export { finaliseHighlightedAuthenticatorRow, highlightAuthenticatorRowByAaguid, resolveEntryByAaguid };

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
