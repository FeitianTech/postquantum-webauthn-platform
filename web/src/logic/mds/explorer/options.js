// The options a filter's combobox offers. No DOM.
import { CERTIFICATION_OPTIONS, FILTER_CONFIG, STATUS_OPTIONS } from '../constants.js';
import { formatEnum } from '../formatters.js';

export const NO_MATCHING_OPTIONS = 'No matches';

// A status column's option: its text's first part, before the descriptor.
function statusOption(text) {
    return typeof text === 'string' ? text.split(' • ')[0].trim() : '';
}

// Every value present in the entries, per filter; Certification and Status always
// offer their static statuses too.
export function collectOptionSets(data) {
    const sets = {
        protocol: new Set(),
        certification: new Set(CERTIFICATION_OPTIONS.map(option => formatEnum(option))),
        latestStatus: new Set(STATUS_OPTIONS.map(option => formatEnum(option))),
        userVerification: new Set(),
        attachment: new Set(),
        transports: new Set(),
        keyProtection: new Set(),
        algorithms: new Set(),
    };

    data.forEach(entry => {
        if (entry.protocol) {
            sets.protocol.add(entry.protocol);
        }
        for (const key of ['certification', 'latestStatus']) {
            const option = statusOption(entry[key]);
            if (option) {
                sets[key].add(option);
            }
        }
        entry.userVerificationList.forEach(value => sets.userVerification.add(value));
        entry.attachmentList.forEach(value => sets.attachment.add(value));
        entry.transportsList.forEach(value => sets.transports.add(value));
        entry.keyProtectionList.forEach(value => sets.keyProtection.add(value));
        entry.algorithmsList.forEach(value => sets.algorithms.add(value));
    });

    return sets;
}

// A filter's static options, as shown (formatted).
export function staticFilterOptions(config) {
    if (!Array.isArray(config?.staticOptions)) {
        return [];
    }
    return config.staticOptions.map(option => formatEnum(option)).filter(Boolean);
}

// The values offered, with the filter's static options, without duplicates.
export function mergeFilterOptions(values, config) {
    const optionList = Array.from(values).filter(Boolean);
    optionList.push(...staticFilterOptions(config));
    return Array.from(new Set(optionList));
}

// The list as shown: unique, sorted ignoring case and accents.
export function sortFilterOptions(options) {
    const unique = Array.from(new Set(options.filter(Boolean)));
    unique.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    return unique;
}

// The options containing the typed text, ignoring case; all of them for none.
/**
 * @param {string[]} options
 * @param {string} query
 * @returns {string[]}
 */
export function matchingFilterOptions(options, query) {
    const value = (query || '').trim().toLowerCase();
    if (!value) {
        return [...options];
    }
    return options.filter(option => option.toLowerCase().includes(value));
}

// Every option filter's list, as shown, for the entries loaded (none yet: only
// the static statuses).
/**
 * @param {Array<Record<string, any>>} entries
 * @returns {Record<string, string[]>}
 */
export function explorerFilterOptionLists(entries) {
    const sets = collectOptionSets(entries);
    /** @type {Record<string, string[]>} */
    const lists = {};
    FILTER_CONFIG.forEach(config => {
        if (config.optionsKey) {
            lists[config.key] = sortFilterOptions(mergeFilterOptions(sets[config.optionsKey], config));
        }
    });
    return lists;
}
