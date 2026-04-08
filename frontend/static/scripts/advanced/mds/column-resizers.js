import { createColumnResizerPointerHandlers } from './column-resizers-pointer.js';
import { applyWidthsToCellsInDom } from './column-resizers-apply-widths.js';

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
        return applyWidthsToCellsInDom(cells, widths);
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

    const {
        handleColumnResizeStart,
        handleColumnResizeMove,
        handleColumnResizeEnd,
    } = createColumnResizerPointerHandlers({
        getState,
        isLoading,
        hasLoaded,
        defaultMinColumnWidth,
        ensureColumnMetrics,
        computeColumnMinWidths,
        normaliseColumnWidths,
        applyColumnWidths,
    });

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
