import {base64ToBase64Url} from '../../shared/utils/binary.js';

export function normalizeClientDataString(value) {
    if (typeof value !== 'string') {
        return '';
    }

    const trimmed = value.trim();
    if (!trimmed) {
        return '';
    }

    if (trimmed.includes('-') || trimmed.includes('_')) {
        return trimmed;
    }

    const base64Pattern = /^[A-Za-z0-9+/=]+$/;
    if (base64Pattern.test(trimmed)) {
        try {
            return base64ToBase64Url(trimmed);
        } catch (error) {
            return trimmed;
        }
    }

    return trimmed;
}

export function cloneJson(value) {
    if (!value || typeof value !== 'object') {
        return null;
    }

    try {
        return JSON.parse(JSON.stringify(value));
    } catch (error) {
        return null;
    }
}

export function collectTruthyEntries(...sources) {
    const result = [];
    sources.forEach(source => {
        if (!source) {
            return;
        }
        if (Array.isArray(source)) {
            source.forEach(item => {
                if (item) {
                    result.push(item);
                }
            });
            return;
        }
        result.push(source);
    });
    return result;
}
