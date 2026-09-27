import {
    fetchCredentialArtifactsBulk,
    uploadCredentialArtifact,
} from '../artifacts-client.js';
import {
    SERVER_ARTIFACT_VERSION,
    SHARED_STORAGE_KEY,
} from './constants.js';
import { cloneJsonValue, isNonEmptyString } from './common.js';
import { ensureAdvancedCredentialStorageId } from './id-utils.js';
import { sanitiseRegistrationDetailSnapshot } from './snapshot-sanitize.js';
import {
    persistUnifiedCredentialRecords,
    readStoredCredentials,
    readUnifiedCredentialRecords,
} from './storage-core.js';
import {
    recordHasHeavyData,
    summariseAdvancedCredentialForLocal,
} from './advanced-storage-shaping.js';

let advancedArtifactSyncPromise = null;
let advancedSnapshotSyncPromise = null;

async function synchroniseAdvancedCredentialArtifacts() {
    const records = readStoredCredentials(SHARED_STORAGE_KEY);
    if (!Array.isArray(records) || !records.length) {
        return false;
    }

    let changed = false;
    const updatedRecords = [];

    // readStoredCredentials keeps only objects; one without a type is simple.
    for (const record of records) {
        if ((record.type || 'simple') !== 'advanced') {
            updatedRecords.push(record);
            continue;
        }

        const working = { ...record, type: 'advanced' };
        const storageId = ensureAdvancedCredentialStorageId(working);

        const needsUpload = (
            !working.hasServerArtifact
            || Number(working.artifactVersion) < SERVER_ARTIFACT_VERSION
        ) && recordHasHeavyData(record);

        let artifactAvailable = Boolean(working.hasServerArtifact);

        if (needsUpload && storageId) {
            const artifactRecord = cloneJsonValue(record);
            const payload = {
                schemaVersion: SERVER_ARTIFACT_VERSION,
                storedCredential: artifactRecord,
            };
            const uploaded = await uploadCredentialArtifact(storageId, payload, { merge: true });
            if (uploaded) {
                artifactAvailable = true;
            }
        }

        let recordForStorage = record;
        if (artifactAvailable) {
            // Always a new object, so the stored copy changes.
            recordForStorage = summariseAdvancedCredentialForLocal(working, storageId, { hasArtifact: artifactAvailable });
            changed = true;
        }

        updatedRecords.push(recordForStorage);

        if (
            artifactAvailable
            && (
                !working.hasServerArtifact
                || Number(working.artifactVersion) < SERVER_ARTIFACT_VERSION
                || recordHasHeavyData(record)
            )
        ) {
            changed = true;
        }
    }

    if (changed) {
        persistUnifiedCredentialRecords(updatedRecords);
    }

    return changed;
}

async function synchroniseAdvancedCredentialSnapshots() {
    const records = readUnifiedCredentialRecords();
    if (!Array.isArray(records) || !records.length) {
        return false;
    }

    const missingStorageIds = [];
    const seen = new Set();

    // The unified read gives only objects, each typed.
    records.forEach(record => {
        if (record.type !== 'advanced') {
            return;
        }

        if (record.registrationDetailSnapshot && typeof record.registrationDetailSnapshot === 'object') {
            return;
        }
        if (!record.hasServerArtifact) {
            return;
        }

        const storageId = isNonEmptyString(record.storageId)
            ? record.storageId.trim()
            : (isNonEmptyString(record.localStorageId) ? record.localStorageId.trim() : '');
        if (!storageId || seen.has(storageId)) {
            return;
        }

        seen.add(storageId);
        missingStorageIds.push(storageId);
    });

    if (!missingStorageIds.length) {
        return false;
    }

    // An object whatever the server answered (artifacts-client.js).
    const artifacts = await fetchCredentialArtifactsBulk(missingStorageIds);

    let changed = false;
    const updatedRecords = records.map(record => {
        if (record.type !== 'advanced') {
            return record;
        }

        const storageId = isNonEmptyString(record.storageId)
            ? record.storageId.trim()
            : (isNonEmptyString(record.localStorageId) ? record.localStorageId.trim() : '');
        if (!storageId) {
            return record;
        }

        const artifact = artifacts[storageId];
        if (!artifact || typeof artifact !== 'object') {
            return record;
        }

        const snapshotCandidate = artifact.registrationDetailSnapshot
            || artifact.storedCredential?.registrationDetailSnapshot;
        const snapshot = sanitiseRegistrationDetailSnapshot(snapshotCandidate);
        if (!snapshot) {
            return record;
        }

        changed = true;
        return {
            ...record,
            registrationDetailSnapshot: snapshot,
            hasServerArtifact: true,
            artifactVersion: SERVER_ARTIFACT_VERSION,
        };
    });

    if (changed) {
        persistUnifiedCredentialRecords(updatedRecords);
    }

    return changed;
}

export function ensureAdvancedCredentialArtifactsSynced() {
    if (!advancedArtifactSyncPromise) {
        advancedArtifactSyncPromise = synchroniseAdvancedCredentialArtifacts()
            .catch(error => {
                console.warn('Failed to synchronise advanced credential artifacts', error);
                return false;
            })
            .finally(() => {
                advancedArtifactSyncPromise = null;
            });
    }
    return advancedArtifactSyncPromise;
}

export function ensureAdvancedCredentialSnapshotsPrefetched() {
    if (!advancedSnapshotSyncPromise) {
        advancedSnapshotSyncPromise = synchroniseAdvancedCredentialSnapshots()
            .catch(error => {
                console.warn('Failed to prefetch advanced credential snapshots', error);
                return false;
            })
            .finally(() => {
                advancedSnapshotSyncPromise = null;
            });
    }
    return advancedSnapshotSyncPromise;
}
