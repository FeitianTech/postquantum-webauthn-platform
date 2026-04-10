import {
    cloneAdvancedStoredRecord,
} from './local/advanced-storage-shaping.js';
import {
    ensureAdvancedCredentialArtifactsSynced,
    ensureAdvancedCredentialSnapshotsPrefetched,
} from './local/advanced-sync.js';
import {
    clearAdvancedCredentials,
    getAllAdvancedCredentials,
    prepareAdvancedCredentialsForServer,
    removeAdvancedCredential,
    saveAdvancedCredential,
    updateAdvancedCredentialRegistrationSnapshot,
    updateAdvancedCredentialSignCount,
} from './local/advanced-credentials.js';
import { readUnifiedCredentialRecords } from './local/storage-core.js';
import {
    clearSimpleCredentials,
    getAllSimpleCredentials,
    getSimpleCredentialsForEmail,
    prepareCredentialsForServer,
    removeSimpleCredential,
    saveSimpleCredential,
    updateSimpleCredentialSignCount,
} from './local/simple-credentials.js';

function cloneCredential(record) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    return { ...record };
}

export function getAllStoredCredentialsInOrder() {
    const orderedRecords = readUnifiedCredentialRecords();
    if (!Array.isArray(orderedRecords) || !orderedRecords.length) {
        return [];
    }

    return orderedRecords
        .map(record => {
            if (!record || typeof record !== 'object') {
                return null;
            }

            if ((record.type || 'simple') === 'advanced') {
                const clone = cloneAdvancedStoredRecord(record);
                return clone || null;
            }

            const clone = cloneCredential(record);
            if (!clone) {
                return null;
            }
            clone.type = clone.type === 'advanced' ? 'advanced' : 'simple';
            return clone;
        })
        .filter(Boolean);
}

export {
    ensureAdvancedCredentialArtifactsSynced,
    ensureAdvancedCredentialSnapshotsPrefetched,
    getAllSimpleCredentials,
    getSimpleCredentialsForEmail,
    saveSimpleCredential,
    removeSimpleCredential,
    clearSimpleCredentials,
    updateSimpleCredentialSignCount,
    prepareCredentialsForServer,
    getAllAdvancedCredentials,
    saveAdvancedCredential,
    removeAdvancedCredential,
    clearAdvancedCredentials,
    updateAdvancedCredentialSignCount,
    updateAdvancedCredentialRegistrationSnapshot,
    prepareAdvancedCredentialsForServer,
};

export default {

};
