import { extractByteArray } from './extractors.js';

export function formatGuidCandidate(value) {
    if (value === undefined || value === null) {
        return '';
    }

    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return '';
        }
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
            return trimmed.toLowerCase();
        }
        const clean = trimmed.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
        if (clean.length === 32) {
            return `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${clean.slice(12, 16)}-${clean.slice(16, 20)}-${clean.slice(20)}`;
        }
        return '';
    }

    const bytes = extractByteArray(value);
    if (bytes && bytes.length === 16) {
        const hex = bytes.map(byte => byte.toString(16).padStart(2, '0')).join('');
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }

    try {
        if (typeof value.toString === 'function') {
            return formatGuidCandidate(value.toString());
        }
    } catch (error) {
        // Ignore conversion errors.
    }
    return '';
}

export function normaliseAaguid(value) {
    const formatted = formatGuidCandidate(value);
    return formatted ? formatted.toLowerCase() : '';
}