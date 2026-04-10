import { updateCredentialSnapshot as uploadSnapshotToServer } from '../credential-artifacts-client.js';
import { SERVER_ARTIFACT_VERSION } from './constants.js';
import { isNonEmptyString } from './common.js';
import { sanitiseRegistrationDetailSnapshot } from './snapshot-sanitize.js';
import {
    persistUnifiedCredentialRecords,
    readUnifiedCredentialRecords,
} from './storage-core.js';

export async function updateAdvancedCredentialRegistrationSnapshot(storageId, snapshot) {
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    if (!storageKey || !snapshot || typeof snapshot !== 'object') {
        return false;
    }

    const sanitisedSnapshot = sanitiseRegistrationDetailSnapshot(snapshot);
    if (!sanitisedSnapshot) {
        return false;
    }

    const records = readUnifiedCredentialRecords();
    let changed = false;
    const updatedRecords = records.map(record => {
        if (!record || typeof record !== 'object' || (record.type || 'simple') !== 'advanced') {
            return record;
        }

        const recordStorageId = isNonEmptyString(record.storageId)
            ? record.storageId.trim()
            : (isNonEmptyString(record.localStorageId) ? record.localStorageId.trim() : '');
        if (recordStorageId !== storageKey) {
            return record;
        }

        changed = true;
        return {
            ...record,
            registrationDetailSnapshot: sanitisedSnapshot,
            hasServerArtifact: true,
            artifactVersion: SERVER_ARTIFACT_VERSION,
        };
    });

    if (changed) {
        persistUnifiedCredentialRecords(updatedRecords);
    }

    const uploaded = await uploadSnapshotToServer(storageKey, sanitisedSnapshot);
    return changed || uploaded;
}
