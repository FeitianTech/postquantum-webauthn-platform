export function setHighlightedRowInState(state, row, key, options = {}, deps = {}) {
    const { scrollRowIntoView, focusRowButton, scheduleScrollTopButtonUpdate } = deps;
    const { scroll = false, behavior = 'smooth', focus = false } = options;

    if (!state || !(row instanceof HTMLElement)) {
        return false;
    }

    if (state.highlightedRow && state.highlightedRow !== row) {
        state.highlightedRow.classList.remove('mds-row--highlight');
    }

    if (!row.classList.contains('mds-row--highlight')) {
        row.classList.add('mds-row--highlight');
    }

    state.highlightedRow = row;
    if (key) {
        state.highlightedRowKey = key;
    }

    if (scroll) {
        scrollRowIntoView(row, { behavior });
    }

    if (focus) {
        focusRowButton(row);
    }

    scheduleScrollTopButtonUpdate();
    return true;
}

export function applyRowHeightLockToRow(row, height) {
    if (!(row instanceof HTMLTableRowElement) || !Number.isFinite(height) || height <= 0) {
        return;
    }

    const heightPx = `${height}px`;
    row.style.height = heightPx;
    row.style.maxHeight = heightPx;
    row.style.minHeight = heightPx;

    Array.from(row.cells ?? []).forEach(cell => {
        if (!(cell instanceof HTMLTableCellElement)) {
            return;
        }
        cell.style.height = heightPx;
        cell.style.maxHeight = heightPx;
        cell.style.minHeight = heightPx;
        cell.style.overflow = 'hidden';
    });
}

export function lockRowHeightsInState(state, deps = {}) {
    const { applyRowHeightLock = applyRowHeightLockToRow } = deps;

    if (!state?.tableBody) {
        return;
    }

    const rows = Array.from(state.tableBody.rows ?? []).filter(row =>
        row instanceof HTMLTableRowElement && !row.classList.contains('mds-empty-row'),
    );

    rows.forEach(row => {
        if (!(row instanceof HTMLTableRowElement)) {
            return;
        }
        if (row.offsetParent === null) {
            return;
        }

        const stored = Number.parseInt(row.dataset.baseHeight || '', 10);
        let baseHeight = Number.isFinite(stored) && stored > 0 ? stored : null;

        if (!baseHeight) {
            const rect = typeof row.getBoundingClientRect === 'function' ? row.getBoundingClientRect() : null;
            const measured = rect && Number.isFinite(rect.height) ? Math.ceil(rect.height) : 0;
            if (!measured) {
                return;
            }
            baseHeight = measured;
            row.dataset.baseHeight = String(baseHeight);
        }

        applyRowHeightLock(row, baseHeight);
    });
}
