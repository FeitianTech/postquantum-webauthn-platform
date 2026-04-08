export function createColumnResizerController({
    getState,
    isLoading,
    hasLoaded,
    defaultMinColumnWidth,
    scheduleColumnResizerMetricsUpdate,
    scheduleHorizontalScrollMetricsUpdate,
    scheduleRowHeightLock,
}) {
    function normaliseColumnWidths(widths) {
        if (!Array.isArray(widths)) {
            return [];
        }
        return widths.map(value => {
            if (!Number.isFinite(value) || value <= 0) {
                return defaultMinColumnWidth;
            }
            return Math.max(Math.round(value), defaultMinColumnWidth);
        });
    }

    function applyWidthsToCells(cells, widths) {
        if (!cells || !widths) {
            return;
        }

        let columnIndex = 0;
        Array.from(cells).forEach(cell => {
            const span = cell.colSpan || 1;
            if (span === 1) {
                const width = widths[columnIndex];
                if (width && Number.isFinite(width)) {
                    const widthPx = `${width}px`;
                    cell.style.width = widthPx;
                    cell.style.minWidth = widthPx;
                    cell.style.maxWidth = widthPx;
                }
            }
            columnIndex += span;
        });
    }

    function computeColumnMinWidths(state = getState()) {
        if (!state?.table?.tHead) {
            return [];
        }

        const headerRow = state.table.tHead.rows[0];
        if (!headerRow) {
            return [];
        }

        const columnCount = headerRow.cells.length;
        if (!columnCount) {
            return [];
        }

        return new Array(columnCount).fill(defaultMinColumnWidth);
    }

    function applyColumnWidths(widths) {
        const state = getState();
        if (!state?.table || !Array.isArray(widths) || !widths.length) {
            return;
        }

        state.table.style.tableLayout = 'fixed';

        const tableHead = state.table.tHead;
        if (tableHead) {
            Array.from(tableHead.rows).forEach(row => applyWidthsToCells(row.cells, widths));
        }

        if (state.tableBody) {
            Array.from(state.tableBody.rows).forEach(row => applyWidthsToCells(row.cells, widths));
        }

        scheduleColumnResizerMetricsUpdate();
        scheduleHorizontalScrollMetricsUpdate();
        scheduleRowHeightLock();
    }

    function stabiliseColumnWidths() {
        const state = getState();
        if (!state?.table) {
            return;
        }
        if (state.root instanceof HTMLElement && state.root.offsetParent === null) {
            return;
        }

        const updateMinWidths = () => {
            const measured = computeColumnMinWidths(state);
            if (measured.length) {
                state.columnMinWidths = measured;
            }
        };

        updateMinWidths();

        if (!Array.isArray(state.columnWidths) || !state.columnWidths.length) {
            requestAnimationFrame(() => {
                const currentState = getState();
                if (!currentState?.table) {
                    return;
                }

                updateMinWidths();

                const headerCells = currentState.table.querySelectorAll('thead tr:first-child th');
                if (!headerCells.length) {
                    return;
                }
                const widths = Array.from(headerCells).map(cell => Math.round(cell.getBoundingClientRect().width));
                if (!widths.length || widths.some(width => width === 0)) {
                    if (currentState) {
                        currentState.columnWidthAttempts = (currentState.columnWidthAttempts || 0) + 1;
                        if (currentState.columnWidthAttempts < 5) {
                            requestAnimationFrame(stabiliseColumnWidths);
                        }
                    }
                    return;
                }
                const normalised = normaliseColumnWidths(widths);
                currentState.columnWidths = normalised;
                currentState.columnWidthAttempts = 0;
                applyColumnWidths(normalised);
            });
            return;
        }

        const adjusted = normaliseColumnWidths(state.columnWidths);
        state.columnWidths = adjusted;
        applyColumnWidths(adjusted);
    }

    function updateColumnResizerMetrics() {
        const state = getState();
        if (!state?.table || !(state.table instanceof HTMLElement)) {
            return;
        }

        const table = state.table;
        if (table.offsetParent === null) {
            table.style.setProperty('--mds-resizer-extend', '0px');
            return;
        }

        const headerRow = table.tHead?.rows?.[0];
        if (!headerRow) {
            table.style.setProperty('--mds-resizer-extend', '0px');
            return;
        }

        let headerHeight = 0;
        if (typeof headerRow.getBoundingClientRect === 'function') {
            const rect = headerRow.getBoundingClientRect();
            if (rect && Number.isFinite(rect.height)) {
                headerHeight = rect.height;
            }
        }
        if (!headerHeight && headerRow instanceof HTMLElement) {
            headerHeight = headerRow.offsetHeight || 0;
        }

        const tableHeight = table.offsetHeight || 0;
        const extend = Math.max(Math.round(tableHeight - headerHeight), 0);
        table.style.setProperty('--mds-resizer-extend', `${extend}px`);
    }

    function ensureColumnMetrics(state = getState()) {
        if (!state?.table?.tHead) {
            return false;
        }
        const headerRow = state.table.tHead.rows[0];
        if (!headerRow) {
            return false;
        }

        const columnCount = headerRow.cells.length;
        if (!columnCount) {
            return false;
        }

        const minWidths = computeColumnMinWidths(state);
        if (minWidths.length) {
            state.columnMinWidths = minWidths;
        }
        if (!Array.isArray(state.columnMinWidths) || state.columnMinWidths.length < columnCount) {
            const fallback = new Array(columnCount).fill(defaultMinColumnWidth);
            if (Array.isArray(state.columnMinWidths)) {
                state.columnMinWidths.forEach((value, index) => {
                    fallback[index] = Math.max(defaultMinColumnWidth, Math.round(value || 0));
                });
            }
            state.columnMinWidths = fallback;
        } else {
            state.columnMinWidths = state.columnMinWidths.map(value =>
                Math.max(defaultMinColumnWidth, Math.round(value || 0)),
            );
        }

        let widths;
        if (!Array.isArray(state.columnWidths) || state.columnWidths.length < columnCount) {
            widths = Array.from(headerRow.cells).map(cell => {
                const rect = cell.getBoundingClientRect();
                const rectWidth = Number.isFinite(rect?.width) ? Math.round(rect.width) : defaultMinColumnWidth;
                return Math.max(rectWidth, defaultMinColumnWidth);
            });
        } else {
            widths = state.columnWidths.slice();
        }

        state.columnWidths = normaliseColumnWidths(widths);
        return true;
    }

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
                } catch (error) {
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

    function setColumnResizersEnabled(enabled, state = getState()) {
        if (!state) {
            return;
        }

        const allow = Boolean(enabled);
        state.columnResizersEnabled = allow;

        if (!allow && state.columnResizeState) {
            handleColumnResizeEnd();
        }

        const resizers = Array.isArray(state.columnResizers) ? state.columnResizers : [];
        resizers.forEach(resizer => {
            if (!(resizer instanceof HTMLElement)) {
                return;
            }
            resizer.classList.toggle('is-disabled', !allow);
            if (allow) {
                resizer.removeAttribute('aria-disabled');
            } else {
                resizer.setAttribute('aria-disabled', 'true');
            }
        });

        if (allow) {
            scheduleColumnResizerMetricsUpdate();
        }
    }

    function setupColumnResizers(state = getState()) {
        if (!state?.table?.tHead) {
            return;
        }
        const headerRow = state.table.tHead.rows[0];
        if (!headerRow) {
            return;
        }

        state.columnResizers = Array.isArray(state.columnResizers) ? state.columnResizers : [];

        Array.from(headerRow.cells).forEach((cell, index) => {
            if (!cell || index === headerRow.cells.length - 1) {
                return;
            }
            if (cell.querySelector('.mds-column-resizer')) {
                return;
            }
            const resizer = document.createElement('div');
            resizer.className = 'mds-column-resizer';
            resizer.dataset.columnIndex = String(index);
            resizer.setAttribute('aria-hidden', 'true');
            resizer.setAttribute('role', 'presentation');
            resizer.tabIndex = -1;
            resizer.title = 'Drag to resize column';
            resizer.addEventListener('pointerdown', handleColumnResizeStart);
            resizer.addEventListener('click', event => {
                event.preventDefault();
                event.stopPropagation();
            });
            cell.appendChild(resizer);
            state.columnResizers.push(resizer);
        });

        scheduleColumnResizerMetricsUpdate();
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
            } catch (error) {
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
        stabiliseColumnWidths,
        applyColumnWidths,
        updateColumnResizerMetrics,
        applyWidthsToCells,
        normaliseColumnWidths,
        computeColumnMinWidths,
        ensureColumnMetrics,
        setColumnResizersEnabled,
        setupColumnResizers,
        handleColumnResizeStart,
        handleColumnResizeMove,
        handleColumnResizeEnd,
    };
}
