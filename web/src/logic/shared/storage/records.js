// The saved credentials, as both tabs read and write them: one localStorage
// array of simple and advanced records (local/constants.js), read once and then
// kept in step with every save (local/storage-core.js). It reads no page.
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
import { followStoredCredentialChanges, readUnifiedCredentialRecords } from './local/storage-core.js';
import {
    clearSimpleCredentials,
    getAllSimpleCredentials,
    getSimpleCredentialsForEmail,
    prepareCredentialsForServer,
    removeSimpleCredential,
    saveSimpleCredential,
    updateSimpleCredentialSignCount,
} from './local/simple-credentials.js';

// Every record, simple and advanced, in the order stored. The unified read gives
// only objects typed "simple" or "advanced" (local/storage-core.js); each is a
// copy, so a caller cannot change the stored records by changing it.
export function getAllStoredCredentialsInOrder() {
    return readUnifiedCredentialRecords().map(record => (
        record.type === 'advanced' ? cloneAdvancedStoredRecord(record) : { ...record }
    ));
}

export {
    followStoredCredentialChanges,
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
