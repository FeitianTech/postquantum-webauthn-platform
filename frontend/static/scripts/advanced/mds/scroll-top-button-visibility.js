export function updateScrollTopButtonVisibilityInState(state, options = {}) {
    if (!state?.scrollTopButton) {
        return;
    }

    const {
        forceHidden = false,
        hideScrollTopButtonFn = () => {},
        showScrollTopButtonFn = () => {},
    } = options;

    if (forceHidden) {
        hideScrollTopButtonFn(state);
        return;
    }

    if (!state.root || state.root.offsetParent === null) {
        hideScrollTopButtonFn(state);
        return;
    }

    if (state.tableContainer?.hidden) {
        hideScrollTopButtonFn(state);
        return;
    }

    const rows = Array.from(state.tableBody?.rows ?? []).filter(row => !row.classList.contains('mds-empty-row'));
    if (rows.length <= 5) {
        hideScrollTopButtonFn(state);
        return;
    }

    const markerIndex = Math.min(4, rows.length - 1);
    const markerRow = rows[markerIndex];
    if (!markerRow || typeof markerRow.getBoundingClientRect !== 'function') {
        hideScrollTopButtonFn(state);
        return;
    }

    const rowRect = markerRow.getBoundingClientRect();
    if (!rowRect || !Number.isFinite(rowRect.top)) {
        hideScrollTopButtonFn(state);
        return;
    }

    const containerRect = state.tableContainer?.getBoundingClientRect?.();
    const headerRect = state.table?.tHead?.getBoundingClientRect?.();
    const boundaryCandidates = [0];
    if (containerRect && Number.isFinite(containerRect.top)) {
        boundaryCandidates.push(containerRect.top);
    }
    if (headerRect && Number.isFinite(headerRect.bottom)) {
        boundaryCandidates.push(headerRect.bottom);
    }
    const boundary = Math.max(...boundaryCandidates);
    const shouldShow = rowRect.top < boundary;

    if (shouldShow) {
        showScrollTopButtonFn(state);
    } else {
        hideScrollTopButtonFn(state);
    }
}
