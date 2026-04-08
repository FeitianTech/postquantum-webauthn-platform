import { resetSortFiltersInState } from './sort-filter-reset.js';
import { normaliseSortValueInput } from './sort-filter-normalise.js';

export const SORT_NONE = 'none';
export const SORT_ASCENDING = 'asc';
export const SORT_DESCENDING = 'desc';

export const DEFAULT_SORT_KEY = 'dateUpdated';
export const DEFAULT_SORT_DIRECTION = SORT_DESCENDING;

const SORT_SEQUENCE = {
    [SORT_NONE]: SORT_ASCENDING,
    [SORT_ASCENDING]: SORT_DESCENDING,
    [SORT_DESCENDING]: SORT_NONE,
};

const SORT_SEQUENCE_OVERRIDES = {
    [DEFAULT_SORT_KEY]: {
        [SORT_NONE]: DEFAULT_SORT_DIRECTION,
        [SORT_ASCENDING]: SORT_DESCENDING,
        [SORT_DESCENDING]: SORT_ASCENDING,
    },
};

const SORT_ACCESSORS = {
    icon: entry => {
        const name = typeof entry?.name === 'string' ? entry.name : '';
        return `${entry?.icon ? '1' : '0'}_${name}`;
    },
    name: entry => entry?.name || '',
    protocol: entry => entry?.protocol || '',
    certification: entry => entry?.certification || '',
    id: entry => entry?.id || '',
    userVerification: entry => entry?.userVerification || '',
    attachment: entry => entry?.attachment || '',
    transports: entry => entry?.transports || '',
    keyProtection: entry => entry?.keyProtection || '',
    algorithms: entry => entry?.algorithms || '',
    algorithmInfo: entry => entry?.algorithmInfo || entry?.certificateAlgorithmInfo || '',
    commonName: entry => entry?.commonName || entry?.certificateCommonNames || '',
    dateUpdated: entry => {
        if (entry?.dateTooltip) {
            const timestamp = Date.parse(entry.dateTooltip);
            if (!Number.isNaN(timestamp)) {
                return timestamp;
            }
            return entry.dateTooltip;
        }
        return entry?.dateUpdated || '';
    },
};

export function createSortFilterController({
    getState,
    getAllData,
    getFilteredData,
    setFilteredData,
    renderTable,
    updateCount,
    normaliseEnumKey,
}) {
    function matchesFilters(entry, filters) {
        const state = getState();
        return Object.entries(filters).every(([key, value]) => {
            if (!value) {
                return true;
            }
            const query = value.toLowerCase();
            if (key === 'certification') {
                const canonicalQuery = normaliseEnumKey(value);
                const dropdown = state?.dropdowns?.certification;
                const options = dropdown?.options || [];
                const isKnownOption = Boolean(canonicalQuery)
                    && options.some(option => normaliseEnumKey(option) === canonicalQuery);

                if (isKnownOption && canonicalQuery) {
                    const statusKey = normaliseEnumKey(entry.certificationStatus);
                    if (canonicalQuery === 'FIDO_CERTIFIED') {
                        if (statusKey) {
                            return statusKey.startsWith('FIDO_CERTIFIED');
                        }
                        const displayKey = normaliseEnumKey((entry.certification || '').split('•')[0]);
                        return displayKey.startsWith('FIDO_CERTIFIED');
                    }
                    if (statusKey) {
                        return statusKey === canonicalQuery;
                    }
                    const displayKey = normaliseEnumKey((entry.certification || '').split('•')[0]);
                    return displayKey === canonicalQuery;
                }

                const haystacks = [entry.certification, entry.certificationStatus]
                    .map(text => (text || '').toLowerCase())
                    .filter(Boolean);
                return haystacks.some(text => text.includes(query));
            }
            const haystack = (entry[key] || '').toLowerCase();
            return haystack.includes(query);
        });
    }

    function compareSortValues(entryA, entryB, accessor) {
        const valueA = accessor(entryA);
        const valueB = accessor(entryB);

        const normalisedA = normaliseSortValueInput(valueA);
        const normalisedB = normaliseSortValueInput(valueB);

        if (normalisedA < normalisedB) {
            return -1;
        }
        if (normalisedA > normalisedB) {
            return 1;
        }

        const fallbackA = String(valueA ?? '').toLowerCase();
        const fallbackB = String(valueB ?? '').toLowerCase();
        if (fallbackA < fallbackB) {
            return -1;
        }
        if (fallbackA > fallbackB) {
            return 1;
        }

        const originalA = String(valueA ?? '');
        const originalB = String(valueB ?? '');
        if (originalA < originalB) {
            return -1;
        }
        if (originalA > originalB) {
            return 1;
        }

        const indexA = typeof entryA?.index === 'number' ? entryA.index : 0;
        const indexB = typeof entryB?.index === 'number' ? entryB.index : 0;
        return indexA - indexB;
    }

    function applySorting(entries) {
        if (!Array.isArray(entries)) {
            return [];
        }

        const state = getState();
        if (!state?.sort) {
            return entries.slice();
        }

        const { key, direction } = state.sort;
        if (!key || direction === SORT_NONE) {
            return entries.slice();
        }

        const accessor = SORT_ACCESSORS[key];
        if (typeof accessor !== 'function') {
            return entries.slice();
        }

        const sorted = entries.slice().sort((a, b) => compareSortValues(a, b, accessor));
        if (direction === SORT_DESCENDING) {
            sorted.reverse();
        }
        return sorted;
    }

    function getNextSortDirection(sortKey, currentDirection) {
        const key = typeof sortKey === 'string' ? sortKey : '';
        const direction = currentDirection || SORT_NONE;
        const override = key && SORT_SEQUENCE_OVERRIDES[key];
        if (override && Object.prototype.hasOwnProperty.call(override, direction)) {
            return override[direction];
        }
        return SORT_SEQUENCE[direction] || SORT_ASCENDING;
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
                let suffix = ' (no sorting)';
                if (appliedDirection === SORT_ASCENDING) {
                    suffix = ' (ascending)';
                } else if (appliedDirection === SORT_DESCENDING) {
                    suffix = ' (descending)';
                }
                button.setAttribute('aria-label', `Sort ${label}${suffix}`);
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

        const key = typeof sortKey === 'string' ? sortKey : '';
        if (!key || !Object.prototype.hasOwnProperty.call(SORT_ACCESSORS, key)) {
            return;
        }

        if (!state.sort) {
            state.sort = { key: DEFAULT_SORT_KEY, direction: DEFAULT_SORT_DIRECTION };
        }

        const currentKey = state.sort.key;
        const currentDirection = state.sort.direction || SORT_NONE;
        const baseDirection = currentKey === key ? currentDirection : SORT_NONE;
        const nextDirection = getNextSortDirection(key, baseDirection);

        if (nextDirection === SORT_NONE) {
            resetSortState();
        } else {
            state.sort.key = key;
            state.sort.direction = nextDirection;
        }

        if (nextDirection !== SORT_NONE) {
            updateSortButtonState();
        }
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
