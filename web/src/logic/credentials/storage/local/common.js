/**
 * @param {unknown} value
 * @returns {value is string}
 */
export function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim() !== '';
}

// Called with a record and a list of its keys (advanced-storage-shaping.js).
export function removeObjectKeys(target, keys) {
    keys.forEach(key => {
        if (Object.hasOwn(target, key)) {
            delete target[key];
        }
    });
}

export function truncateString(value, maxLength) {
    if (typeof value !== 'string') {
        return '';
    }
    if (!Number.isFinite(maxLength) || maxLength <= 0) {
        return value;
    }
    return value.length > maxLength ? value.slice(0, maxLength) : value;
}

export function safeParse(json) {
    if (typeof json !== 'string') {
        return [];
    }
    try {
        const parsed = JSON.parse(json);
        if (Array.isArray(parsed)) {
            return parsed.filter(item => item && typeof item === 'object');
        }
    } catch (error) {
        // Ignore parse errors and fall back to empty list.
    }
    return [];
}

export function computeUpdatedSignCount(currentValue, signCount) {
    if (typeof signCount === 'number' && Number.isFinite(signCount)) {
        return signCount;
    }
    if (typeof currentValue === 'number' && Number.isFinite(currentValue)) {
        return currentValue + 1;
    }
    return 1;
}
