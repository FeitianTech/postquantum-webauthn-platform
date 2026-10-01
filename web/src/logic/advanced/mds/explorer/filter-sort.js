// How the explorer's filters match and its columns sort. No DOM.
import { normaliseSortValueInput } from '../sort-filter-normalise.js';

import { normaliseEnumKey } from '../utils/formatters.js';


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

export const MDS_SORT_ACCESSORS = {
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

export function defaultExplorerSort() {
    return { key: DEFAULT_SORT_KEY, direction: DEFAULT_SORT_DIRECTION };
}

function certificationDisplayKey(entry) {
    return normaliseEnumKey((entry.certification || '').split('•')[0]);
}

// Whether an entry passes every filter (all must). A filter is the text typed or
// picked, found in the column's text ignoring case. Certification: text naming
// one of the list's options must equal the entry's status, except "FIDO
// Certified", which every certified level passes.
export function matchesExplorerFilters(entry, filters, certificationOptions = []) {
    return Object.entries(filters).every(([key, value]) => {
        if (!value) {
            return true;
        }
        const query = value.toLowerCase();
        if (key === 'certification') {
            const canonicalQuery = normaliseEnumKey(value);
            const isKnownOption = Boolean(canonicalQuery)
                && certificationOptions.some(option => normaliseEnumKey(option) === canonicalQuery);

            if (isKnownOption && canonicalQuery) {
                const statusKey = normaliseEnumKey(entry.certificationStatus);
                if (canonicalQuery === 'FIDO_CERTIFIED') {
                    if (statusKey) {
                        return statusKey.startsWith('FIDO_CERTIFIED');
                    }
                    return certificationDisplayKey(entry).startsWith('FIDO_CERTIFIED');
                }
                if (statusKey) {
                    return statusKey === canonicalQuery;
                }
                return certificationDisplayKey(entry) === canonicalQuery;
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

// Ties go to the lower-cased text, then the text, then the entry's index.
export function compareExplorerSortValues(entryA, entryB, accessor) {
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

// A copy of the entries in the sort's order; descending is ascending reversed.
export function sortExplorerEntries(entries, sort) {
    if (!Array.isArray(entries)) {
        return [];
    }
    if (!sort) {
        return entries.slice();
    }

    const { key, direction } = sort;
    if (!key || direction === SORT_NONE) {
        return entries.slice();
    }

    const accessor = MDS_SORT_ACCESSORS[key];
    if (typeof accessor !== 'function') {
        return entries.slice();
    }

    const sorted = entries.slice().sort((a, b) => compareExplorerSortValues(a, b, accessor));
    if (direction === SORT_DESCENDING) {
        sorted.reverse();
    }
    return sorted;
}

export function nextExplorerSortDirection(sortKey, currentDirection) {
    const key = typeof sortKey === 'string' ? sortKey : '';
    const direction = currentDirection || SORT_NONE;
    const override = key && SORT_SEQUENCE_OVERRIDES[key];
    if (override && Object.hasOwn(override, direction)) {
        return override[direction];
    }
    return SORT_SEQUENCE[direction] || SORT_ASCENDING;
}

export function isExplorerSortKey(key) {
    return typeof key === 'string' && Boolean(key) && Object.hasOwn(MDS_SORT_ACCESSORS, key);
}

// The sort after a click on a column's sort control: another column starts from
// none; reaching none restores the default. Null for a column that does not sort.
export function nextExplorerSort(sort, key) {
    if (!isExplorerSortKey(key)) {
        return null;
    }
    const current = sort || defaultExplorerSort();
    const baseDirection = current.key === key ? current.direction || SORT_NONE : SORT_NONE;
    const nextDirection = nextExplorerSortDirection(key, baseDirection);
    return nextDirection === SORT_NONE ? defaultExplorerSort() : { key, direction: nextDirection };
}

export function filterAndSortExplorerEntries(entries, filters, sort, certificationOptions = []) {
    const matched = entries.filter(entry => matchesExplorerFilters(entry, filters, certificationOptions));
    return sortExplorerEntries(matched, sort);
}

export function countActiveExplorerFilters(filters) {
    return Object.values(filters || {}).filter(value => typeof value === 'string' && value.trim()).length;
}
