import { resetSortFiltersInState } from './sort-filter-reset.js';
import { normaliseSortValueInput } from './sort-filter-normalise.js';
import {
    DEFAULT_SORT_DIRECTION,
    DEFAULT_SORT_KEY,
    SORT_NONE,
    compareExplorerSortValues,
    explorerSortLabel,
    isExplorerSortKey,
    matchesExplorerFilters,
    nextExplorerSort,
    nextExplorerSortDirection,
    sortExplorerEntries,
} from './explorer/filter-sort.js';

export {
    DEFAULT_SORT_DIRECTION,
    DEFAULT_SORT_KEY,
    SORT_ASCENDING,
    SORT_DESCENDING,
    SORT_NONE,
} from './explorer/filter-sort.js';

export function createSortFilterController({
    getState,
    getAllData,
    getFilteredData,
    setFilteredData,
    renderTable,
    updateCount,
}) {
    function matchesFilters(entry, filters) {
        const state = getState();
        const options = state?.dropdowns?.certification?.options || [];
        return matchesExplorerFilters(entry, filters, options);
    }

    function compareSortValues(entryA, entryB, accessor) {
        return compareExplorerSortValues(entryA, entryB, accessor);
    }

    function applySorting(entries) {
        return sortExplorerEntries(entries, getState()?.sort);
    }

    function getNextSortDirection(sortKey, currentDirection) {
        return nextExplorerSortDirection(sortKey, currentDirection);
    }

    function updateSortButtonState() {
        const state = getState();
        if (!state?.sortButtons) {
            return;
        }

        const activeKey = state.sort?.key || '';
        const direction = state.sort?.direction || SORT_NONE;

        state.sortButtons.forEach((button, key) => {
            const isActive = key === activeKey && direction !== SORT_NONE;
            const appliedDirection = isActive ? direction : SORT_NONE;
            button.setAttribute('data-sort-direction', appliedDirection);
            button.setAttribute('aria-pressed', isActive ? 'true' : 'false');

            const label = button.getAttribute('data-sort-label') || '';
            if (label) {
                button.setAttribute('aria-label', explorerSortLabel(label, appliedDirection));
            }

            const headerCell = button.closest('th');
            if (headerCell) {
                headerCell.classList.toggle('mds-sort-active', isActive);
            }
        });
    }

    function resetSortState() {
        const state = getState();
        if (!state) {
            return;
        }
        if (!state.sort) {
            state.sort = { key: DEFAULT_SORT_KEY, direction: DEFAULT_SORT_DIRECTION };
        } else {
            state.sort.key = DEFAULT_SORT_KEY;
            state.sort.direction = DEFAULT_SORT_DIRECTION;
        }
        updateSortButtonState();
    }

    function applyFilters(options = {}) {
        const state = getState();
        if (!state) {
            return;
        }

        const { preserveTableScroll = false } = options;
        const allData = getAllData();

        const activeFilters = state.filters;
        const matched = allData.filter(entry => matchesFilters(entry, activeFilters));
        const sorted = applySorting(matched);
        setFilteredData(sorted);
        renderTable(sorted, { preserveTableScroll });
        updateCount(sorted.length, allData.length);
        updateSortButtonState();
    }

    function handleSortButtonClick(sortKey) {
        const state = getState();
        if (!state) {
            return;
        }

        if (!isExplorerSortKey(sortKey)) {
            return;
        }

        if (!state.sort) {
            state.sort = { key: DEFAULT_SORT_KEY, direction: DEFAULT_SORT_DIRECTION };
        }

        const next = nextExplorerSort(state.sort, sortKey);
        state.sort.key = next.key;
        state.sort.direction = next.direction;
        updateSortButtonState();
        applyFilters({ preserveTableScroll: true });
    }

    function resetFilters() {
        return resetSortFiltersInState(getState, getFilteredData, getAllData, applyFilters);
    }

    return {
        matchesFilters,
        applySorting,
        compareSortValues,
        normaliseSortValue: normaliseSortValueInput,
        getNextSortDirection,
        updateSortButtonState,
        resetSortState,
        applyFilters,
        handleSortButtonClick,
        resetFilters,
    };
}
