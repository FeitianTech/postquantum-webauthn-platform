import {
    fetchCredentialArtifactsBulk,
    uploadCredentialArtifact,
} from '../artifacts-client.js';
import {
    SERVER_ARTIFACT_VERSION,
} from './constants.js';
import { cloneJson } from '../../../shared/json.js';
import { isNonEmptyString } from './common.js';
import { buildRecordKey, ensureAdvancedCredentialStorageId } from './id-utils.js';
import { sanitiseRegistrationDetailSnapshot } from './snapshot-sanitize.js';
import {
    persistUnifiedCredentialRecords,
    readUnifiedCredentialRecords,
} from './storage-core.js';
import {
    recordHasHeavyData,
    summariseAdvancedCredentialForLocal,
} from './advanced-storage-shaping.js';

let advancedArtifactSyncPromise = null;
let advancedSnapshotSyncPromise = null;

async function synchroniseAdvancedCredentialArtifacts() {
    // The unified read, so records still under the legacy keys are among them
    // when the write below removes those keys.
    const records = readUnifiedCredentialRecords();
    // Each record kept on the server, by its key (as saves match records), with
    // the storage id its artifact is under.
    const kept = new Map();

    // The unified read gives only objects, each typed.
    for (const record of records) {
        if (record.type !== 'advanced') {
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
            const artifactRecord = cloneJson(record);
            const payload = {
                schemaVersion: SERVER_ARTIFACT_VERSION,
                storedCredential: artifactRecord,
            };
            const uploaded = await uploadCredentialArtifact(storageId, payload, { merge: true });
            if (uploaded) {
                artifactAvailable = true;
            }
        }

        if (artifactAvailable) {
            kept.set(buildRecordKey(record), storageId);
        }
    }

    // Read again after the uploads, so what the person saved, changed or deleted
    // meanwhile stays; only the records kept on the server are summarised.
    let changed = false;
    const updatedRecords = readUnifiedCredentialRecords().map(record => {
        const storageId = kept.get(buildRecordKey(record));
        if (!storageId) {
            return record;
        }
        const summary = summariseAdvancedCredentialForLocal(record, storageId, { hasArtifact: true });
        // A change only when the stored copy is not already this summary:
        // a record summarised by an earlier warm-up is left as it is, so
        // the list is not read again (nor other tabs woken) for nothing.
        if (JSON.stringify(summary) !== JSON.stringify(record)) {
            changed = true;
        }
        return summary;
    });

    if (changed) {
        persistUnifiedCredentialRecords(updatedRecords);
    }

    return changed;
}

function hasSnapshot(record) {
    return Boolean(record.registrationDetailSnapshot) && typeof record.registrationDetailSnapshot === 'object';
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

        if (hasSnapshot(record)) {
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

    // Read again after the fetch, so what the person saved, changed or deleted
    // meanwhile stays; a record that has a snapshot by now keeps it.
    let changed = false;
    const updatedRecords = readUnifiedCredentialRecords().map(record => {
        if (record.type !== 'advanced' || hasSnapshot(record)) {
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
            // A sync that fails is tried again at the next load.
            .catch(() => false)
            .finally(() => {
                advancedArtifactSyncPromise = null;
            });
    }
    return advancedArtifactSyncPromise;
}

export function ensureAdvancedCredentialSnapshotsPrefetched() {
    if (!advancedSnapshotSyncPromise) {
        advancedSnapshotSyncPromise = synchroniseAdvancedCredentialSnapshots()
            .catch(() => false)
            .finally(() => {
                advancedSnapshotSyncPromise = null;
            });
    }
    return advancedSnapshotSyncPromise;
}
