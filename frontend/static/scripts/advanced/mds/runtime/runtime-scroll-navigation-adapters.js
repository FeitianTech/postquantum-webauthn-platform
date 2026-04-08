export function createMdsScrollNavigationAdapters(config = {}) {
    const {
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
        getScheduleScrollTopButtonUpdate,
        getScheduleColumnResizerMetricsUpdate,
        getScheduleHorizontalScrollMetricsUpdate,
    } = config;

    let isSyncingHorizontalScroll = false;

    function clearHorizontalFloatingStyles(horizontal) {
        return clearHorizontalFloatingStylesInDom(horizontal);
    }

    function hideHorizontalScroll(state = getState()) {
        return hideHorizontalScrollInState(state, clearHorizontalFloatingStyles);
    }

    function updateFloatingHorizontalScrollPosition(state = getState(), metrics = {}) {
        return updateFloatingHorizontalScrollPositionInState(state, metrics, {
            clearHorizontalFloatingStylesFn: clearHorizontalFloatingStyles,
            sideMargin: floatingScrollSideMargin,
            bottomMargin: floatingScrollBottomMargin,
        });
    }

    function updateHorizontalScrollMetrics(state = getState()) {
        return updateHorizontalScrollMetricsInState(state, {
            hideHorizontalScrollFn: hideHorizontalScroll,
            updateFloatingHorizontalScrollPositionFn: updateFloatingHorizontalScrollPosition,
            getIsSyncing: () => isSyncingHorizontalScroll,
            setIsSyncing: value => {
                isSyncingHorizontalScroll = Boolean(value);
            },
            clearHorizontalFloatingStylesFn: clearHorizontalFloatingStyles,
        });
    }

    function syncHorizontalScrollPositions(source, target) {
        return syncHorizontalScrollPositionsInDom(
            source,
            target,
            () => isSyncingHorizontalScroll,
            value => {
                isSyncingHorizontalScroll = Boolean(value);
            },
        );
    }

    async function waitForLayoutSettled() {
        await waitForLayoutSettledInDom();
    }

    function waitForStateReady({ timeout = 5000 } = {}) {
        return waitForStateReadyInDom(() => getState(), { timeout });
    }

    function waitForRowByKey(key, { attempts = 60 } = {}) {
        return waitForRowByKeyInDom(key, {
            getState,
            findRowByKey,
            attempts,
        });
    }

    function scrollRowIntoView(row, { behavior = 'smooth' } = {}) {
        return scrollRowIntoViewInDom(row, { behavior });
    }

    function focusRowButton(row) {
        return focusRowButtonInDom(row);
    }

    function setHighlightedRow(row, key, { scroll = false, behavior = 'smooth', focus = false } = {}) {
        return setHighlightedRowInState(
            getState(),
            row,
            key,
            { scroll, behavior, focus },
            {
                scrollRowIntoView,
                focusRowButton,
                scheduleScrollTopButtonUpdate: getScheduleScrollTopButtonUpdate(),
            },
        );
    }

    function lockRowHeights() {
        return lockRowHeightsInState(getState(), {
            applyRowHeightLock,
        });
    }

    function applyRowHeightLock(row, height) {
        return applyRowHeightLockToRow(row, height);
    }

    function updateScrollTopButtonVisibility(options = {}) {
        return updateScrollTopButtonVisibilityInState(getState(), {
            ...options,
            hideScrollTopButtonFn: hideScrollTopButton,
            showScrollTopButtonFn: showScrollTopButton,
        });
    }

    function showScrollTopButton() {
        return showScrollTopButtonInState(getState());
    }

    function hideScrollTopButton() {
        return hideScrollTopButtonInState(getState());
    }

    function scrollMdsSectionToTop() {
        return scrollMdsSectionToTopInState(getState(), getScheduleScrollTopButtonUpdate());
    }

    function handleWindowScroll() {
        return handleWindowScrollEvents(
            getScheduleScrollTopButtonUpdate(),
            getScheduleColumnResizerMetricsUpdate(),
            getScheduleHorizontalScrollMetricsUpdate(),
        );
    }

    return {
        clearHorizontalFloatingStyles,
        hideHorizontalScroll,
        updateFloatingHorizontalScrollPosition,
        updateHorizontalScrollMetrics,
        syncHorizontalScrollPositions,
        waitForLayoutSettled,
        waitForStateReady,
        waitForRowByKey,
        scrollRowIntoView,
        focusRowButton,
        setHighlightedRow,
        lockRowHeights,
        applyRowHeightLock,
        updateScrollTopButtonVisibility,
        showScrollTopButton,
        hideScrollTopButton,
        scrollMdsSectionToTop,
        handleWindowScroll,
    };
}
