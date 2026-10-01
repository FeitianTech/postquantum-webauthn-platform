import { base64ToBytes, bytesToBase64Url } from '../../../shared/base64.js';
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

// A stored identifier as base64url. Base64url (hex digits included, as before)
// is kept as it is; standard base64 is decoded strictly and the same bytes
// re-spelled. Anything else is returned as written rather than read as some
// other bytes.
export function ensureBase64Url(value) {
    if (typeof value !== 'string' || !value.trim()) {
        return '';
    }
    const trimmed = value.trim();
    if (/^[A-Za-z0-9_-]+$/.test(trimmed)) {
        return trimmed;
    }
    try {
        return bytesToBase64Url(base64ToBytes(trimmed));
    } catch (error) {
        return trimmed;
    }
}

export function ensureAdvancedCredentialStorageId(record) {
    if (!record || typeof record !== 'object') {
        return '';
    }

    const existing = isNonEmptyString(record.storageId) ? record.storageId.trim() : '';
    if (existing) {
        record.storageId = existing;
        return existing;
    }

    const baseId = normaliseAdvancedCredentialId(record);
    const randomSegment = crypto.randomUUID();
    const parts = [];
    if (baseId) {
        parts.push(baseId);
    }
    parts.push(Date.now().toString(36));
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
    return `${typed.type}:generated:${crypto.randomUUID()}`;
}
