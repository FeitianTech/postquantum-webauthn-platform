import { formatKey } from '../labels.js';

const ENCODED_FORMAT_ORDER = ['hex', 'base64', 'base64url', 'colonHex'];
const ENCODED_FORMAT_SKIP_KEYS = new Set(['encoding']);

function looksLikeBinarySummary(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }

    if (typeof value.hex === 'string' && value.hex.trim()) {
        return true;
    }

    if (typeof value.base64 === 'string' && value.base64.trim()) {
        return true;
    }

    if (typeof value.base64url === 'string' && value.base64url.trim()) {
        return true;
    }

    return false;
}

function resolveSummaryLabel(label) {
    const friendly = label ? formatKey(label) : 'Encoded output';
    return friendly.toLowerCase() === 'binary' ? 'Encoded output' : friendly;
}

export function findEncodedSummary(value, label = '') {
    if (value === null || value === undefined) {
        return null;
    }

    if (Array.isArray(value)) {
        for (const item of value) {
            const result = findEncodedSummary(item, label);
            if (result) {
                return result;
            }
        }

        return null;
    }

    if (typeof value !== 'object') {
        return null;
    }

    if (looksLikeBinarySummary(value)) {
        return {
            summary: value,
            label: resolveSummaryLabel(label),
        };
    }

    if (value.binary && looksLikeBinarySummary(value.binary)) {
        return {
            summary: value.binary,
            label: resolveSummaryLabel(label),
        };
    }

    for (const [key, nested] of Object.entries(value)) {
        const result = findEncodedSummary(nested, key);
        if (result) {
            return result;
        }
    }

    return null;
}

/**
 * The views of the encoded bytes, each `{key, label, value}`: Hex, Base64,
 * Base64url and Colon Hex first, then any other string the summary holds
 * (not `encoding`); blank ones are left out.
 */
export function listEncodedFormats(summary) {
    if (!summary || typeof summary !== 'object') {
        return [];
    }

    const formats = [];
    const usedKeys = new Set();
    const add = (key, value) => {
        if (typeof value !== 'string' || !value.trim()) {
            return;
        }
        formats.push({ key, label: formatKey(key), value });
        usedKeys.add(key);
    };

    ENCODED_FORMAT_ORDER.forEach((key) => add(key, summary[key]));
    Object.entries(summary).forEach(([key, value]) => {
        if (!usedKeys.has(key) && !ENCODED_FORMAT_SKIP_KEYS.has(key)) {
            add(key, value);
        }
    });
    return formats;
}

function encodedByteLength(summary) {
    const byteLength = typeof summary?.byteLength === 'number'
        ? summary.byteLength
        : summary?.length;
    return typeof byteLength === 'number' && Number.isFinite(byteLength) ? byteLength : null;
}

/**
 * The encoded bytes an encoder answer holds: the section's label, the views and
 * the byte length (null when the summary gives none). Null when the answer has
 * no summary.
 */
export function describeEncodedOutput(data) {
    const summaryInfo = findEncodedSummary(data);
    if (!summaryInfo) {
        return null;
    }
    // A summary is found by a hex, base64 or base64url that is not blank, so it
    // always has a view to show.
    return {
        label: summaryInfo.label,
        formats: listEncodedFormats(summaryInfo.summary),
        byteLength: encodedByteLength(summaryInfo.summary),
    };
}
