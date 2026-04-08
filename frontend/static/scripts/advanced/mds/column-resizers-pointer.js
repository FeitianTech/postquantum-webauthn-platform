export function createColumnResizerPointerHandlers({
    getState,
    isLoading,
    hasLoaded,
    defaultMinColumnWidth,
    ensureColumnMetrics,
    computeColumnMinWidths,
    normaliseColumnWidths,
    applyColumnWidths,
}) {
    function handleColumnResizeEnd(event) {
        const state = getState();
        const resizeState = state?.columnResizeState;
        if (!resizeState) {
            return;
        }

        const target = resizeState.activeResizer;
        if (target instanceof HTMLElement) {
            target.classList.remove('is-active');
            if (typeof target.releasePointerCapture === 'function' && resizeState.pointerId !== undefined) {
                try {
                    target.releasePointerCapture(resizeState.pointerId);
                } catch {
                    // Ignore errors when releasing capture.
                }
            }
        }

        const listenerTarget = resizeState.listenerTarget || target;
        if (listenerTarget) {
            listenerTarget.removeEventListener('pointermove', handleColumnResizeMove);
            listenerTarget.removeEventListener('pointerup', handleColumnResizeEnd);
            listenerTarget.removeEventListener('pointercancel', handleColumnResizeEnd);
        }

        if (state.tableContainer) {
            state.tableContainer.classList.remove('mds-table-container--resizing');
        }

        state.columnResizeState = null;
        if (event) {
            event.preventDefault();
            event.stopPropagation();
        }

        const minWidths = computeColumnMinWidths(state);
        if (minWidths.length) {
            state.columnMinWidths = minWidths;
        }
        if (Array.isArray(state.columnWidths)) {
            const normalised = normaliseColumnWidths(state.columnWidths);
            state.columnWidths = normalised;
            applyColumnWidths(normalised);
        }
    }

    function handleColumnResizeStart(event) {
        const state = getState();
        if (!state) {
            return;
        }
        if (event.button !== undefined && event.button !== 0) {
            return;
        }
        const target = event.currentTarget;
        if (!(target instanceof HTMLElement)) {
            return;
        }
        if (isLoading() || !hasLoaded() || !state.columnResizersEnabled) {
            event.preventDefault();
            event.stopPropagation();
            return;
        }
        const columnIndex = Number.parseInt(target.dataset.columnIndex || '', 10);
        if (!Number.isFinite(columnIndex)) {
            return;
        }

        if (!ensureColumnMetrics(state)) {
            return;
        }

        const widths = Array.isArray(state.columnWidths) ? state.columnWidths.slice() : [];
        if (columnIndex >= widths.length - 1) {
            return;
        }

        const startLeft = widths[columnIndex];
        if (!Number.isFinite(startLeft)) {
            return;
        }

        const minWidths = Array.isArray(state.columnMinWidths) ? state.columnMinWidths : [];
        let minLeft = Number.isFinite(minWidths[columnIndex]) ? Math.round(minWidths[columnIndex]) : defaultMinColumnWidth;
        if (!Number.isFinite(minLeft) || minLeft <= 0) {
            minLeft = defaultMinColumnWidth;
        }
        minLeft = Math.max(minLeft, defaultMinColumnWidth);

        event.preventDefault();
        event.stopPropagation();

        const resizeState = {
            activeResizer: target,
            columnIndex,
            pointerId: event.pointerId,
            startX: event.clientX,
            startLeft,
            minLeft,
            listenerTarget: target,
        };

        state.columnResizeState = resizeState;

        if (state.tableContainer) {
            state.tableContainer.classList.add('mds-table-container--resizing');
        }

        target.classList.add('is-active');

        let useDocumentListeners = false;
        if (typeof target.setPointerCapture === 'function') {
            try {
                target.setPointerCapture(event.pointerId);
            } catch {
                useDocumentListeners = true;
            }
        } else {
            useDocumentListeners = true;
        }

        if (useDocumentListeners && typeof document !== 'undefined') {
            resizeState.listenerTarget = document;
        }

        const listenerTarget = resizeState.listenerTarget;
        if (listenerTarget) {
            listenerTarget.addEventListener('pointermove', handleColumnResizeMove);
            listenerTarget.addEventListener('pointerup', handleColumnResizeEnd);
            listenerTarget.addEventListener('pointercancel', handleColumnResizeEnd);
        }
    }

    function handleColumnResizeMove(event) {
        const state = getState();
        if (!state?.columnResizeState) {
            return;
        }
        const resizeState = state.columnResizeState;
        if (resizeState.pointerId !== undefined && event.pointerId !== undefined && resizeState.pointerId !== event.pointerId) {
            return;
        }

        const widths = Array.isArray(state.columnWidths) ? state.columnWidths.slice() : [];
        if (!widths.length) {
            return;
        }

        const leftIndex = resizeState.columnIndex;
        if (!Number.isFinite(leftIndex) || leftIndex < 0 || leftIndex >= widths.length) {
            return;
        }

        const minLeft = resizeState.minLeft || defaultMinColumnWidth;

        let delta = event.clientX - resizeState.startX;
        if (!Number.isFinite(delta)) {
            delta = 0;
        }
        const maxNegativeDelta = resizeState.startLeft - minLeft;
        if (Number.isFinite(maxNegativeDelta) && maxNegativeDelta >= 0) {
            delta = Math.max(delta, -maxNegativeDelta);
        }

        let newLeft = resizeState.startLeft + delta;
        if (!Number.isFinite(newLeft)) {
            newLeft = resizeState.startLeft;
        }

        widths[leftIndex] = Math.max(minLeft, Math.round(newLeft));

        state.columnWidths = widths;
        const normalised = normaliseColumnWidths(widths);
        state.columnWidths = normalised;
        applyColumnWidths(normalised);

        if (typeof window !== 'undefined' && window.getSelection) {
            const selection = window.getSelection();
            if (selection && typeof selection.removeAllRanges === 'function') {
                selection.removeAllRanges();
            }
        }

        event.preventDefault();
        event.stopPropagation();
    }

    return {
        handleColumnResizeStart,
        handleColumnResizeMove,
        handleColumnResizeEnd,
    };
}
