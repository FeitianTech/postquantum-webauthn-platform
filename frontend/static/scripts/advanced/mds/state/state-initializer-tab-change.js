export function registerMdsTabChangeHandler(
    state,
    {
        clearRowHighlight,
        hideScrollTopButton,
        hideHorizontalScroll,
        scheduleScrollTopButtonUpdate,
        scheduleHorizontalScrollMetricsUpdate,
    } = {},
) {
    const handleTabChanged = event => {
        if (event?.detail?.tab !== 'mds') {
            clearRowHighlight();
            hideScrollTopButton();
            hideHorizontalScroll(state);
        } else {
            scheduleScrollTopButtonUpdate();
            scheduleHorizontalScrollMetricsUpdate();
        }
    };

    if (typeof document !== 'undefined') {
        document.addEventListener('tab:changed', handleTabChanged);
    }

    return handleTabChanged;
}
