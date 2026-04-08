import { createMdsScrollNavigationAdapters } from './runtime-scroll-navigation-adapters.js';
import { createMdsSchedulers } from './runtime-schedulers.js';
import { createColumnResizerController } from './column-resizers.js';
import { createSortFilterController } from './sort-filter-controller.js';
import {
    clearHorizontalFloatingStyles as clearHorizontalFloatingStylesInDom,
    handleWindowScroll as handleWindowScrollEvents,
    hideHorizontalScroll as hideHorizontalScrollInState,
    hideScrollTopButton as hideScrollTopButtonInState,
    scrollMdsSectionToTop as scrollMdsSectionToTopInState,
    showScrollTopButton as showScrollTopButtonInState,
    syncHorizontalScrollPositions as syncHorizontalScrollPositionsInDom,
    updateFloatingHorizontalScrollPosition as updateFloatingHorizontalScrollPositionInState,
    updateHorizontalScrollMetrics as updateHorizontalScrollMetricsInState,
    updateScrollTopButtonVisibility as updateScrollTopButtonVisibilityInState,
} from './scroll-metrics.js';
import {
    focusRowButton as focusRowButtonInDom,
    scrollRowIntoView as scrollRowIntoViewInDom,
    waitForLayoutSettled as waitForLayoutSettledInDom,
    waitForRowByKey as waitForRowByKeyInDom,
    waitForStateReady as waitForStateReadyInDom,
} from './navigation-utils.js';
import {
    applyRowHeightLockToRow,
    lockRowHeightsInState,
    setHighlightedRowInState,
} from './row-layout.js';

export function createScrollControllers({
    getState,
    findRowByKey,
    isLoading,
    hasLoaded,
    getAllData,
    getFilteredData,
    setFilteredData,
    renderTable,
    updateCount,
    normaliseEnumKey,
    defaultMinColumnWidth = 64,
    floatingScrollSideMargin = 16,
    floatingScrollBottomMargin = 24,
}) {
    let scheduleScrollTopButtonUpdate;
    let scheduleColumnResizerMetricsUpdate;
    let scheduleRowHeightLock;
    let scheduleHorizontalScrollMetricsUpdate;
    let columnResizerController;

    const scrollAdapters = createMdsScrollNavigationAdapters({
        getState,
        clearHorizontalFloatingStylesInDom,
        hideHorizontalScrollInState,
        updateFloatingHorizontalScrollPositionInState,
        updateHorizontalScrollMetricsInState,
        syncHorizontalScrollPositionsInDom,
        floatingScrollSideMargin,
        floatingScrollBottomMargin,
        waitForLayoutSettledInDom,
        waitForStateReadyInDom,
        waitForRowByKeyInDom,
        scrollRowIntoViewInDom,
        focusRowButtonInDom,
        findRowByKey,
        setHighlightedRowInState,
        lockRowHeightsInState,
        applyRowHeightLockToRow,
        updateScrollTopButtonVisibilityInState,
        showScrollTopButtonInState,
        hideScrollTopButtonInState,
        scrollMdsSectionToTopInState,
        handleWindowScrollEvents,
        getScheduleScrollTopButtonUpdate: () => scheduleScrollTopButtonUpdate,
        getScheduleColumnResizerMetricsUpdate: () => scheduleColumnResizerMetricsUpdate,
        getScheduleHorizontalScrollMetricsUpdate: () => scheduleHorizontalScrollMetricsUpdate,
    });

    ({
        scheduleScrollTopButtonUpdate,
        scheduleColumnResizerMetricsUpdate,
        scheduleRowHeightLock,
        scheduleHorizontalScrollMetricsUpdate,
    } = createMdsSchedulers({
        updateScrollTopButtonVisibility: scrollAdapters.updateScrollTopButtonVisibility,
        updateColumnResizerMetrics: () => columnResizerController?.updateColumnResizerMetrics(),
        lockRowHeights: scrollAdapters.lockRowHeights,
        updateHorizontalScrollMetrics: scrollAdapters.updateHorizontalScrollMetrics,
    }));

    columnResizerController = createColumnResizerController({
        getState,
        isLoading,
        hasLoaded,
        defaultMinColumnWidth,
        scheduleColumnResizerMetricsUpdate: () => scheduleColumnResizerMetricsUpdate(),
        scheduleHorizontalScrollMetricsUpdate: () => scheduleHorizontalScrollMetricsUpdate(),
        scheduleRowHeightLock: () => scheduleRowHeightLock(),
    });

    const sortFilterController = createSortFilterController({
        getState,
        getAllData,
        getFilteredData,
        setFilteredData,
        renderTable,
        updateCount,
        normaliseEnumKey,
    });

    return {
        ...scrollAdapters,
        scheduleScrollTopButtonUpdate,
        scheduleColumnResizerMetricsUpdate,
        scheduleRowHeightLock,
        scheduleHorizontalScrollMetricsUpdate,
        columnResizerController,
        sortFilterController,
    };
}
