// The fields and chip lists of the explorer's authenticator page: a value as
// the metadata writes it, and a field or a list only when it has one. No DOM.
import { formatDetailValue } from '../formatters.js';

/**
 * A field: a value (an identifier is copyable, in Geist Mono), or a list of codes.
 * @typedef {{ label: string, value?: string, codes?: string[], identifier?: boolean }} DetailField
 * @typedef {{ label: string, values: string[] }} ChipList
 */

export function extractList(value) {
    if (!value) {
        return [];
    }
    if (Array.isArray(value)) {
        return value.filter(Boolean);
    }
    return [value];
}

// One list item (never null: the list reader drops empty items first).
export function rawDisplayString(value) {
    if (typeof value === 'string') {
        return value;
    }
    if (typeof value === 'number' || typeof value === 'bigint') {
        return String(value);
    }
    try {
        // true as "true", an object as its JSON; a function or a symbol has no
        // JSON: nothing to show.
        return JSON.stringify(value) ?? '';
    } catch {
        try {
            return String(value);
        } catch {
            return '';
        }
    }
}

// A list's values as the metadata writes them (a number as written, a boolean
// as true / false, an object as its JSON), the empty ones left out.
export function rawListValues(value) {
    return extractList(value)
        .map(item => rawDisplayString(item))
        .filter(text => text !== '');
}

// A field is shown when it has a value that is not blank.
export function field(label, value, { identifier = false } = {}) {
    if (value === undefined || value === null) {
        return null;
    }
    const text = String(value);
    if (!text.trim()) {
        return null;
    }
    return identifier ? { label, value: text, identifier: true } : { label, value: text };
}

export function present(items) {
    return items.filter(Boolean);
}

export function chipList(label, value) {
    const values = rawListValues(value);
    return values.length ? { label, values } : null;
}

// A descriptor's properties as "Label: value", joined by " • ", each only when
// the descriptor has it; '' for no descriptor.
export function describe(descriptor, properties) {
    if (!descriptor || typeof descriptor !== 'object') {
        return '';
    }
    return properties
        .filter(([key]) => descriptor[key] !== undefined)
        .map(([key, label]) => `${label}: ${descriptor[key]}`)
        .join(' • ');
}

// "fipsRevision" -> "Fips Revision": a field no MDS version this page knows,
// named from its key.
export function nameFromKey(key) {
    const words = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2');
    return words.charAt(0).toUpperCase() + words.slice(1);
}

// A value on one line: a list's values joined by commas, an object as its JSON.
export function valueText(value) {
    if (Array.isArray(value)) {
        return value.map(valueText).join(', ');
    }
    if (value && typeof value === 'object') {
        return JSON.stringify(value);
    }
    return formatDetailValue(value);
}
