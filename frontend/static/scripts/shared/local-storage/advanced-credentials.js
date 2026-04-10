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
import { updateAdvancedCredentialRegistrationSnapshot } from './advanced-snapshot-update.js';

export function getAllAdvancedCredentials() {
    const { advancedRecords } = readAdvancedCredentialPartitions();
    return advancedRecords.map(cloneAdvancedCredential).filter(Boolean);
}

export function saveAdvancedCredential(rawCredential) {
    if (!rawCredential || typeof rawCredential !== 'object') {
        return null;
    }

    const credential = cloneAdvancedCredential(rawCredential);
    if (!credential) {
        return null;
    }

    credential.type = 'advanced';

    const credentialId = normaliseAdvancedCredentialId(credential);
    if (!credentialId) {
        return null;
    }

    credential.credentialIdBase64Url = ensureBase64Url(credentialId);
    let storageId = ensureAdvancedCredentialStorageId(credential, { forceNew: !isNonEmptyString(credential.storageId) });

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

    const filteredAdvanced = [];
    advancedRecords.forEach(record => {
        if (!record || typeof record !== 'object') {
            return;
        }
        const recordStorageId = isNonEmptyString(record.storageId) ? record.storageId.trim() : '';
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

    if (storageId && filteredAdvanced.some(item => item && typeof item === 'object' && item.storageId === storageId)) {
        storageId = ensureAdvancedCredentialStorageId(credential, { forceNew: true });
    }

    const sanitisedStored = filteredAdvanced
        .map(item => prepareAdvancedCredentialForStorage(item))
        .filter(Boolean);
    const sanitisedCredential = prepareAdvancedCredentialForStorage(credential);
    if (!sanitisedCredential) {
        return null;
    }

    const updatedAdvanced = sanitisedStored.concat(sanitisedCredential);
    if (persistCredentialPartitions(filteredSimple, updatedAdvanced, { prepareAdvancedCredentialForStorage })) {
        return sanitisedCredential;
    }

    const aggressivelyTrimmedStored = filteredAdvanced
        .map(item => prepareAdvancedCredentialForStorage(item, { aggressive: true }))
        .filter(Boolean);
    const aggressivelyTrimmedCredential = prepareAdvancedCredentialForStorage(credential, { aggressive: true });
    if (!aggressivelyTrimmedCredential) {
        return null;
    }

    const aggressiveSet = aggressivelyTrimmedStored.concat(aggressivelyTrimmedCredential);
    if (persistCredentialPartitions(filteredSimple, aggressiveSet, { prepareAdvancedCredentialForStorage })) {
        return aggressivelyTrimmedCredential;
    }

    return null;
}

export function removeAdvancedCredential(credentialId, storageId = null) {
    const id = credentialId ? String(credentialId) : '';
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    const { simpleRecords, advancedRecords } = readAdvancedCredentialPartitions();
    const filteredAdvanced = advancedRecords.filter(record => {
        if (!record || typeof record !== 'object') {
            return false;
        }
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

export function clearAdvancedCredentials() {
    const { simpleRecords } = readAdvancedCredentialPartitions();
    persistCredentialPartitions(simpleRecords, [], { prepareAdvancedCredentialForStorage });
}

export function updateAdvancedCredentialSignCount(credentialId, signCount, storageId = null) {
    const id = credentialId ? String(credentialId) : '';
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    if (!id && !storageKey) {
        return false;
    }

    const { simpleRecords, advancedRecords } = readAdvancedCredentialPartitions();
    let updated = false;
    const updatedAdvanced = advancedRecords.map(record => {
        if (!record || typeof record !== 'object') {
            return record;
        }
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
        if (!record || typeof record !== 'object') {
            return record;
        }
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

export { updateAdvancedCredentialRegistrationSnapshot };

export function prepareAdvancedCredentialsForServer(credentials = null) {
    const source = Array.isArray(credentials) ? credentials : getAllAdvancedCredentials();
    return prepareAdvancedCredentialsForServerFromSource(source);
}
