// The options a filter offers, for both UIs: the legacy tab's dropdowns
// (dropdown.js, status-controls.js, state/state-initializer.js) and web's
// comboboxes. No DOM.
import { CERTIFICATION_OPTIONS, FILTER_CONFIG } from '../constants.js';
import { formatEnum } from '../utils/formatters.js';

export const NO_MATCHING_OPTIONS = 'No matches';

// Every value present in the entries, per filter; certification always offers
// the static statuses too.
export function collectOptionSets(data) {
    const sets = {
        protocol: new Set(),
        certification: new Set(CERTIFICATION_OPTIONS.map(option => formatEnum(option))),
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
        if (entry.certificationStatus) {
            sets.certification.add(formatEnum(entry.certificationStatus));
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
export function matchingFilterOptions(options, query) {
    const value = (query || '').trim().toLowerCase();
    if (!value) {
        return [...options];
    }
    return options.filter(option => option.toLowerCase().includes(value));
}

// Every option filter's list, as shown, for the entries loaded (none yet: only
// the static certification statuses).
export function explorerFilterOptionLists(entries) {
    const sets = collectOptionSets(entries);
    const lists = {};
    FILTER_CONFIG.forEach(config => {
        if (config.optionsKey) {
            lists[config.key] = sortFilterOptions(mergeFilterOptions(sets[config.optionsKey], config));
        }
    });
    return lists;
}
