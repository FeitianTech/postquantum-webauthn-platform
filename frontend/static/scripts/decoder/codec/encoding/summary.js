import { formatKey } from '../labels.js';

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
