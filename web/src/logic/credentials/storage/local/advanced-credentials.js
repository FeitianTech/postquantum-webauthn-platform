import { computeUpdatedSignCount, isNonEmptyString } from './common.js';
import {
    ensureAdvancedCredentialStorageId,
    ensureBase64Url,
    normaliseAdvancedCredentialId,
    normaliseCredentialId,
} from './id-utils.js';
import { persistCredentialPartitions } from './partition-core.js';
import {
    cloneAdvancedCredential,
    prepareAdvancedCredentialForStorage,
    readAdvancedCredentialPartitions,
} from './advanced-storage-shaping.js';
import { prepareAdvancedCredentialsForServerFromSource } from './advanced-server-payload.js';

/** @import { SavedCredential } from '../../saved-list.js' */

export function getAllAdvancedCredentials() {
    const { advancedRecords } = readAdvancedCredentialPartitions();
    return advancedRecords.map(cloneAdvancedCredential).filter(Boolean);
}

/**
 * @param {Record<string, any> | null | undefined} rawCredential
 * @returns {(SavedCredential & { storageId?: string }) | null}
 */
export function saveAdvancedCredential(rawCredential) {
    if (!rawCredential || typeof rawCredential !== 'object') {
        return null;
    }

    const credential = cloneAdvancedCredential(rawCredential);
    credential.type = 'advanced';

    const credentialId = normaliseAdvancedCredentialId(credential);
    if (!credentialId) {
        return null;
    }

    credential.credentialIdBase64Url = ensureBase64Url(credentialId);
    const storageId = ensureAdvancedCredentialStorageId(credential);

    const { simpleRecords, advancedRecords } = readAdvancedCredentialPartitions();

    let mergedEmail = credential.email || credential.userName || credential.username || '';
    let mergedSignCount = Number.isFinite(credential.signCount) ? Number(credential.signCount) : null;

    const filteredSimple = simpleRecords.filter(record => {
        const recordId = normaliseCredentialId(record);
        if (recordId !== credentialId) {
            return true;
        }
        if (!mergedEmail) {
            mergedEmail = record.email || record.userName || record.username || '';
        }
        if (!Number.isFinite(mergedSignCount) && Number.isFinite(record.signCount)) {
            mergedSignCount = Number(record.signCount);
        }
        return false;
    });

    // Stored advanced records are objects that each have a storage id
    // (readAdvancedCredentialPartitions). One with this credential's storage id
    // or credential id is replaced, so none left has this storage id.
    const filteredAdvanced = [];
    advancedRecords.forEach(record => {
        const recordStorageId = record.storageId;
        const recordId = normaliseAdvancedCredentialId(record) || normaliseCredentialId(record);
        if ((recordStorageId && storageId && recordStorageId === storageId) || (recordId && recordId === credentialId)) {
            if (!mergedEmail) {
                mergedEmail = record.email || record.userName || record.username || '';
            }
            if (!Number.isFinite(mergedSignCount) && Number.isFinite(record.signCount)) {
                mergedSignCount = Number(record.signCount);
            }
            return;
        }
        filteredAdvanced.push(record);
    });

    credential.email = credential.email || mergedEmail || '';
    if (!credential.userName && mergedEmail) {
        credential.userName = mergedEmail;
    }
    if (!credential.username && mergedEmail) {
        credential.username = mergedEmail;
    }
    if (!Number.isFinite(credential.signCount)) {
        credential.signCount = Number.isFinite(mergedSignCount) ? Number(mergedSignCount) : 0;
    }

    const sanitisedStored = filteredAdvanced.map(item => prepareAdvancedCredentialForStorage(item));
    const sanitisedCredential = prepareAdvancedCredentialForStorage(credential);

    const updatedAdvanced = sanitisedStored.concat(sanitisedCredential);
    if (persistCredentialPartitions(filteredSimple, updatedAdvanced, { prepareAdvancedCredentialForStorage })) {
        return sanitisedCredential;
    }

    const aggressivelyTrimmedStored = filteredAdvanced
        .map(item => prepareAdvancedCredentialForStorage(item, { aggressive: true }));
    const aggressivelyTrimmedCredential = prepareAdvancedCredentialForStorage(credential, { aggressive: true });

    const aggressiveSet = aggressivelyTrimmedStored.concat(aggressivelyTrimmedCredential);
    if (persistCredentialPartitions(filteredSimple, aggressiveSet, { prepareAdvancedCredentialForStorage })) {
        return aggressivelyTrimmedCredential;
    }

    return null;
}

/**
 * @param {unknown} credentialId
 * @param {unknown} [storageId]
 * @returns {boolean}
 */
export function removeAdvancedCredential(credentialId, storageId = null) {
    const id = credentialId ? String(credentialId) : '';
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    const { simpleRecords, advancedRecords } = readAdvancedCredentialPartitions();
    const filteredAdvanced = advancedRecords.filter(record => {
        if (storageKey) {
            return record.storageId !== storageKey;
        }
        if (!id) {
            return true;
        }
        return normaliseAdvancedCredentialId(record) !== id;
    });
    const changed = filteredAdvanced.length !== advancedRecords.length;
    if (changed) {
        persistCredentialPartitions(simpleRecords, filteredAdvanced, { prepareAdvancedCredentialForStorage });
    }
    return changed;
}

/**
 * @param {unknown} credentialId
 * @param {unknown} signCount
 * @param {unknown} [storageId]
 * @returns {boolean}
 */
export function updateAdvancedCredentialSignCount(credentialId, signCount, storageId = null) {
    const id = credentialId ? String(credentialId) : '';
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    if (!id && !storageKey) {
        return false;
    }

    const { simpleRecords, advancedRecords } = readAdvancedCredentialPartitions();
    let updated = false;
    const updatedAdvanced = advancedRecords.map(record => {
        if (storageKey) {
            if (record.storageId !== storageKey) {
                return record;
            }
        } else if (normaliseAdvancedCredentialId(record) !== id) {
            return record;
        }
        const clone = { ...record };
        clone.signCount = computeUpdatedSignCount(clone.signCount, signCount);
        updated = true;
        return clone;
    });

    const updatedSimple = simpleRecords.map(record => {
        const recordId = normaliseCredentialId(record);
        if (!recordId || recordId !== id) {
            return record;
        }
        const clone = { ...record };
        clone.signCount = computeUpdatedSignCount(clone.signCount, signCount);
        updated = true;
        return clone;
    });

    if (updated) {
        persistCredentialPartitions(updatedSimple, updatedAdvanced, { prepareAdvancedCredentialForStorage });
    }

    return updated;
}

/**
 * @param {Array<Record<string, any>> | null} [credentials] The records sent (the stored ones when not given).
 * @returns {Array<Record<string, unknown>>}
 */
export function prepareAdvancedCredentialsForServer(credentials = null) {
    const source = Array.isArray(credentials) ? credentials : getAllAdvancedCredentials();
    return prepareAdvancedCredentialsForServerFromSource(source);
}
