export function resetSortFiltersInState(getState, getFilteredData, getAllData, applyFilters) {
    const state = getState();
    if (!state) {
        return;
    }

    let changed = false;
    Object.entries(state.filters || {}).forEach(([key, value]) => {
        if (value) {
            state.filters[key] = '';
            const input = state.filterInputs[key];
            if (input) {
                input.value = '';
            }
            changed = true;
        }
    });

    const filtered = getFilteredData();
    const allData = getAllData();
    if (changed || (!filtered.length && allData.length)) {
        applyFilters();
    }
}
