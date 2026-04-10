import { isNonEmptyString } from './common.js';

export function normaliseCredentialId(record) {
    if (!record) {
        return '';
    }
    if (typeof record.credentialIdBase64Url === 'string' && record.credentialIdBase64Url) {
        return record.credentialIdBase64Url;
    }
    if (typeof record.credentialId === 'string' && record.credentialId) {
        return record.credentialId;
    }
    if (typeof record.id === 'string' && record.id) {
        return record.id;
    }
    return '';
}

export function normaliseAdvancedCredentialId(record) {
    if (!record) {
        return '';
    }
    const candidates = [
        record.credentialIdBase64Url,
        record.credentialIdBase64URL,
        record.credentialIdBase64,
        record.credentialId,
        record.id,
    ];
    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.trim()) {
            return candidate.trim();
        }
    }
    return '';
}

export function generateRandomIdSegment() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    const random = Math.random().toString(36).slice(2, 11);
    const randomB = Math.random().toString(36).slice(2, 11);
    return `${random}${randomB}`;
}

export function ensureBase64Url(value) {
    if (typeof value !== 'string' || !value.trim()) {
        return '';
    }
    const trimmed = value.trim();
    if (/^[A-Za-z0-9_-]+$/.test(trimmed)) {
        return trimmed;
    }
    try {
        const decoded = atob(trimmed);
        return btoa(decoded).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    } catch (error) {
        try {
            const bytes = new Uint8Array(trimmed.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            let binary = '';
            bytes.forEach(byte => {
                binary += String.fromCharCode(byte);
            });
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        } catch (innerError) {
            return trimmed;
        }
    }
}

export function ensureAdvancedCredentialStorageId(record, { forceNew = false } = {}) {
    if (!record || typeof record !== 'object') {
        return '';
    }

    if (!forceNew) {
        const existing = isNonEmptyString(record.storageId) ? record.storageId.trim() : '';
        if (existing) {
            record.storageId = existing;
            return existing;
        }
    }

    const baseId = normaliseAdvancedCredentialId(record);
    const timestampSource = record.createdAt || record.registrationTime || record.registration_time;
    const timestampValue = isNonEmptyString(timestampSource) ? timestampSource.trim() : '';
    const randomSegment = generateRandomIdSegment();
    const parts = [];
    if (baseId) {
        parts.push(baseId);
    }
    if (timestampValue) {
        parts.push(timestampValue);
    } else {
        parts.push(Date.now().toString(36));
    }
    parts.push(randomSegment);
    const storageId = parts.join('::');
    record.storageId = storageId;
    return storageId;
}

export function ensureRecordType(record, fallbackType = 'simple') {
    if (!record || typeof record !== 'object') {
        return null;
    }
    const clone = { ...record };
    const type = clone.type === 'advanced' ? 'advanced' : (clone.type === 'simple' ? 'simple' : fallbackType);
    clone.type = type === 'advanced' ? 'advanced' : 'simple';
    return clone;
}

export function getRecordIdentifier(record) {
    if (!record || typeof record !== 'object') {
        return '';
    }
    if (isNonEmptyString(record.storageId)) {
        return `storage:${record.storageId.trim()}`;
    }
    const advancedId = normaliseAdvancedCredentialId(record);
    if (advancedId) {
        return `id:${advancedId}`;
    }
    const simpleId = normaliseCredentialId(record);
    if (simpleId) {
        return `id:${simpleId}`;
    }
    return '';
}

export function buildRecordKey(record, fallbackType = 'simple') {
    const typed = ensureRecordType(record, fallbackType);
    if (!typed) {
        return '';
    }
    const identifier = getRecordIdentifier(typed);
    if (identifier) {
        return `${typed.type}:${identifier}`;
    }
    return `${typed.type}:generated:${generateRandomIdSegment()}`;
}
