// A saved advanced credential completed from its server artifact, as its details
// open: the artifact's fields (read as saved records are read) merged into the
// record, and its registration snapshot kept as far as the sanitiser allows and
// saved back. DOM-free.
import {fetchCredentialArtifact} from './storage/artifacts-client.js';
import {updateAdvancedCredentialRegistrationSnapshot} from './storage/local/advanced-credentials.js';
import {migrateStoredRecord} from './storage/local/record-migration.js';
import {sanitiseRegistrationDetailSnapshot} from './storage/local/snapshot-sanitize.js';

export const HYDRATE_TEXT = Object.freeze({
    failed: 'Unable to fetch credential artifact',
});

// Saves the artifact's snapshot back into the record this browser keeps, and
// says so when it was kept.
async function saveSnapshot(storageId, snapshot, onSaved) {
    if (await updateAdvancedCredentialRegistrationSnapshot(storageId, snapshot)) {
        onSaved();
    }
}

/**
 * Completes `cred` in place, once per storage id; marks it `__artifactHydrated`
 * (the storage id, 'missing' or 'error') and gives the artifact's stored
 * credential, or null. A failure changes nothing else. The snapshot the
 * artifact brings is saved, and `onSaved` called once it is.
 * @param {Record<string, any> | null | undefined} cred
 * @param {() => void} onSaved
 * @returns {Promise<Record<string, any> | null>}
 */
export async function hydrateCredentialFromServer(cred, onSaved) {
    if (!cred || typeof cred !== 'object') {
        return null;
    }

    const storageId = cred.storageId || cred.localStorageId || null;
    if (!storageId || typeof storageId !== 'string' || !storageId.trim()) {
        cred.__artifactHydrated = 'missing';
        return null;
    }

    if (cred.__artifactHydrated === storageId) {
        return cred;
    }

    try {
        const artifact = await fetchCredentialArtifact(storageId);
        if (!artifact || typeof artifact !== 'object') {
            cred.__artifactHydrated = 'missing';
            return null;
        }

        // Artifacts saved before this version hold standard base64 where they now
        // hold base64url; read them the way saved records are read.
        const { record: storedCredential } = migrateStoredRecord(
            artifact.storedCredential && typeof artifact.storedCredential === 'object'
                ? artifact.storedCredential
                : artifact,
        );

        if (storedCredential && typeof storedCredential === 'object') {
            Object.keys(storedCredential).forEach(key => {
                if (key !== 'registrationDetailSnapshot') {
                    cred[key] = storedCredential[key];
                }
            });
        }

        // The artifact holds whatever a browser uploaded; its snapshot is kept
        // only as far as the sanitiser allows, like one saved locally.
        const snapshot = sanitiseRegistrationDetailSnapshot(
            artifact.registrationDetailSnapshot || storedCredential?.registrationDetailSnapshot,
        );
        if (snapshot) {
            cred.registrationDetailSnapshot = snapshot;
            void saveSnapshot(storageId, snapshot, onSaved);
        }

        cred.__artifactHydrated = storageId;
        return storedCredential;
    } catch {
        // The details say so (HYDRATE_TEXT.failed), and the next opening asks again.
        cred.__artifactHydrated = 'error';
        return null;
    }
}
