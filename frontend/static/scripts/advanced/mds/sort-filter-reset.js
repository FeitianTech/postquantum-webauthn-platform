import { clearExplorerFilters } from './explorer/filter-sort.js';

export function resetSortFiltersInState(getState, getFilteredData, getAllData, applyFilters) {
    const state = getState();
    if (!state) {
        return;
    }

    const { filters, changed } = clearExplorerFilters(state.filters);
    Object.keys(filters).forEach(key => {
        if (state.filters[key]) {
            state.filters[key] = '';
            const input = state.filterInputs[key];
            if (input) {
                input.value = '';
            }
        }
    });

    const filtered = getFilteredData();
    const allData = getAllData();
    if (changed || (!filtered.length && allData.length)) {
        applyFilters();
    }
}
