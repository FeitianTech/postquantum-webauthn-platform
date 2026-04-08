export function createMdsSchedulers(config = {}) {
    const {
        updateScrollTopButtonVisibility,
        updateColumnResizerMetrics,
        lockRowHeights,
        updateHorizontalScrollMetrics,
    } = config;

    let scrollTopButtonUpdateScheduled = false;
    let columnResizerMetricsScheduled = false;
    let rowHeightLockScheduled = false;
    let horizontalScrollMetricsScheduled = false;

    function scheduleScrollTopButtonUpdate() {
        if (scrollTopButtonUpdateScheduled) {
            return;
        }
        scrollTopButtonUpdateScheduled = true;
        const apply = () => {
            scrollTopButtonUpdateScheduled = false;
            updateScrollTopButtonVisibility();
        };
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(apply);
        } else {
            setTimeout(apply, 0);
        }
    }

    function scheduleColumnResizerMetricsUpdate() {
        if (columnResizerMetricsScheduled) {
            return;
        }
        columnResizerMetricsScheduled = true;
        const apply = () => {
            columnResizerMetricsScheduled = false;
            updateColumnResizerMetrics();
        };
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(apply);
        } else {
            setTimeout(apply, 0);
        }
    }

    function scheduleRowHeightLock() {
        if (rowHeightLockScheduled) {
            return;
        }
        rowHeightLockScheduled = true;
        const apply = () => {
            rowHeightLockScheduled = false;
            lockRowHeights();
        };
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(() => {
                if (typeof requestAnimationFrame === 'function') {
                    requestAnimationFrame(apply);
                } else {
                    setTimeout(apply, 0);
                }
            });
        } else {
            setTimeout(apply, 0);
        }
    }

    function scheduleHorizontalScrollMetricsUpdate() {
        if (horizontalScrollMetricsScheduled) {
            return;
        }
        horizontalScrollMetricsScheduled = true;
        const apply = () => {
            horizontalScrollMetricsScheduled = false;
            updateHorizontalScrollMetrics();
        };
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(apply);
        } else {
            setTimeout(apply, 0);
        }
    }

    return {
        scheduleScrollTopButtonUpdate,
        scheduleColumnResizerMetricsUpdate,
        scheduleRowHeightLock,
        scheduleHorizontalScrollMetricsUpdate,
    };
}
