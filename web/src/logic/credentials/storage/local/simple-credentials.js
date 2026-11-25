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
import { registeredBackupEligible } from '../../record-fields.js';

/**
 * A Simple username as the server reads it (routes/simple/account.py): trimmed as
 * String.prototype.trim trims, then compared exactly, so "Alice" and "alice" are
 * two accounts here as there (tests/fixtures/simple-usernames.json holds both sides).
 * @param {unknown} value
 * @returns {string}
 */
export function simpleUsername(value) {
    return value === null || value === undefined ? '' : String(value).trim();
}

/** The username a saved record names: its email, else its userName, else its username. */
function savedUsername(record) {
    return simpleUsername(record.email || record.userName || record.username);
}

export function getAllSimpleCredentials() {
    const { simple } = partitionRecords(readUnifiedCredentialRecords());
    return simple.map(record => ({ ...record }));
}

export function getSimpleCredentialsForEmail(email) {
    const username = simpleUsername(email);
    if (!username) {
        return [];
    }
    return getAllSimpleCredentials().filter(cred => savedUsername(cred) === username);
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
    const username = simpleUsername(email);

    const filteredSimple = simpleStored.filter(record => {
        const recordId = normaliseCredentialId(record);
        if (recordId !== id) {
            return true;
        }
        return Boolean(username) && savedUsername(record) !== username;
    });

    const changed = filteredSimple.length !== simpleStored.length;
    return changed && persistCredentialPartitions(filteredSimple, advancedStored, {
        prepareAdvancedCredentialForStorage,
    });
}

export function updateSimpleCredentialSignCount(email, credentialId, signCount) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }

    const { simple: simpleStored, advanced: advancedStored } = partitionRecords(readUnifiedCredentialRecords());
    const username = simpleUsername(email);
    let updated = false;

    const updatedSimple = simpleStored.map(record => {
        const recordId = normaliseCredentialId(record);
        if (recordId !== id || (username && savedUsername(record) !== username)) {
            return record;
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

    return updated && persistCredentialPartitions(updatedSimple, updatedAdvanced, {
        prepareAdvancedCredentialForStorage,
    });
}

export function prepareCredentialsForServer(credentials) {
    if (!Array.isArray(credentials) || !credentials.length) {
        return [];
    }
    return credentials
        .filter(item => item && typeof item === 'object')
        .map(item => {
            const credentialId = normaliseCredentialId(item);
            const aaguid = item.aaguid || null;
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
                // What the server compares the assertion's BE with (assertion_checks).
                backupEligible: registeredBackupEligible(item),
            };
        })
        .filter(item => item.credentialId && item.publicKey);
}
