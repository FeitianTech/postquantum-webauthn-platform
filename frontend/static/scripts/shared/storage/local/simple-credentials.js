import { computeUpdatedSignCount } from './common.js';
import {
    normaliseAdvancedCredentialId,
    normaliseCredentialId,
} from './id-utils.js';
import {
    partitionRecords,
    persistCredentialPartitions,
} from './partition-core.js';
import { readUnifiedCredentialRecords } from './storage-core.js';
import { prepareAdvancedCredentialForStorage } from './advanced-storage-shaping.js';

function cloneCredential(record) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    return { ...record };
}

export function getAllSimpleCredentials() {
    const { simple } = partitionRecords(readUnifiedCredentialRecords());
    return simple.map(cloneCredential).filter(Boolean);
}

export function getSimpleCredentialsForEmail(email) {
    if (!email) {
        return [];
    }
    const normalised = String(email).toLowerCase();
    return getAllSimpleCredentials().filter(cred => {
        const storedEmail = cred.email || cred.userName || cred.username;
        return storedEmail && String(storedEmail).toLowerCase() === normalised;
    });
}

export function saveSimpleCredential(rawCredential) {
    if (!rawCredential || typeof rawCredential !== 'object') {
        return null;
    }

    const credential = {
        type: 'simple',
        ...rawCredential,
    };

    if (!credential.email) {
        credential.email = credential.userName || credential.username || '';
    }

    const credentialId = normaliseCredentialId(credential);
    if (!credentialId) {
        return null;
    }

    credential.credentialIdBase64Url = credentialId;
    if (typeof credential.signCount !== 'number' || !Number.isFinite(credential.signCount)) {
        credential.signCount = 0;
    }

    const { simple: simpleStored, advanced: advancedStored } = partitionRecords(readUnifiedCredentialRecords());

    const updatedAdvanced = advancedStored.map(record => {
        const recordId = normaliseAdvancedCredentialId(record) || normaliseCredentialId(record);
        if (recordId !== credentialId) {
            return record;
        }
        const clone = { ...record };
        clone.email = credential.email;
        clone.userName = credential.userName;
        clone.username = credential.username;
        clone.signCount = credential.signCount;
        return clone;
    });

    const advancedHasMatch = updatedAdvanced.some(record => {
        const recordId = normaliseAdvancedCredentialId(record) || normaliseCredentialId(record);
        return recordId === credentialId;
    });

    const filteredSimple = simpleStored.filter(item => normaliseCredentialId(item) !== credentialId);
    if (!advancedHasMatch) {
        filteredSimple.push(credential);
    }

    const success = persistCredentialPartitions(filteredSimple, updatedAdvanced, {
        prepareAdvancedCredentialForStorage,
    });
    return success ? credential : null;
}

export function removeSimpleCredential(credentialId, email) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }

    const { simple: simpleStored, advanced: advancedStored } = partitionRecords(readUnifiedCredentialRecords());
    const normalisedEmail = email ? String(email).toLowerCase() : null;

    const filteredSimple = simpleStored.filter(record => {
        const recordId = normaliseCredentialId(record);
        if (recordId !== id) {
            return true;
        }
        if (normalisedEmail) {
            const recordEmail = record.email || record.userName || record.username;
            return String(recordEmail || '').toLowerCase() !== normalisedEmail;
        }
        return false;
    });

    const changed = filteredSimple.length !== simpleStored.length;
    if (changed) {
        persistCredentialPartitions(filteredSimple, advancedStored, {
            prepareAdvancedCredentialForStorage,
        });
    }
    return changed;
}

export function clearSimpleCredentials() {
    const { advanced } = partitionRecords(readUnifiedCredentialRecords());
    persistCredentialPartitions([], advanced, {
        prepareAdvancedCredentialForStorage,
    });
}

export function updateSimpleCredentialSignCount(email, credentialId, signCount) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }

    const { simple: simpleStored, advanced: advancedStored } = partitionRecords(readUnifiedCredentialRecords());
    const normalisedEmail = email ? String(email).toLowerCase() : null;
    let updated = false;

    const updatedSimple = simpleStored.map(record => {
        const recordId = normaliseCredentialId(record);
        if (recordId !== id) {
            return record;
        }
        if (normalisedEmail) {
            const recordEmail = record.email || record.userName || record.username;
            if (String(recordEmail || '').toLowerCase() !== normalisedEmail) {
                return record;
            }
        }
        const clone = { ...record };
        clone.signCount = computeUpdatedSignCount(clone.signCount, signCount);
        updated = true;
        return clone;
    });

    const updatedAdvanced = advancedStored.map(record => {
        const recordId = normaliseAdvancedCredentialId(record) || normaliseCredentialId(record);
        if (recordId !== id) {
            return record;
        }
        const clone = { ...record };
        clone.signCount = computeUpdatedSignCount(clone.signCount, signCount);
        updated = true;
        return clone;
    });

    if (updated) {
        persistCredentialPartitions(updatedSimple, updatedAdvanced, {
            prepareAdvancedCredentialForStorage,
        });
    }

    return updated;
}

export function prepareCredentialsForServer(credentials) {
    if (!Array.isArray(credentials) || !credentials.length) {
        return [];
    }
    return credentials
        .filter(item => item && typeof item === 'object')
        .map(item => {
            const credentialId = normaliseCredentialId(item);
            const aaguid = item.aaguid || item.aaguidHex || null;
            const publicKey = item.publicKeyBase64Url || item.publicKey || null;
            const algorithm = typeof item.publicKeyAlgorithm === 'number'
                ? item.publicKeyAlgorithm
                : (typeof item.algorithm === 'number' ? item.algorithm : undefined);
            return {
                credentialId,
                aaguid,
                publicKey,
                signCount: Number.isFinite(item.signCount) ? item.signCount : 0,
                algorithm,
            };
        })
        .filter(item => item.credentialId && item.publicKey);
}
