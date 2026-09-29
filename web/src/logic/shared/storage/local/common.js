export function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim() !== '';
}

export function cloneJsonValue(value) {
    if (!value || typeof value !== 'object') {
        return null;
    }
    try {
        return JSON.parse(JSON.stringify(value));
    } catch (error) {
        return { ...value };
    }
}

export function removeObjectKeys(target, keys) {
    if (!target || typeof target !== 'object' || !Array.isArray(keys)) {
        return;
    }
    keys.forEach(key => {
        if (Object.prototype.hasOwnProperty.call(target, key)) {
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
