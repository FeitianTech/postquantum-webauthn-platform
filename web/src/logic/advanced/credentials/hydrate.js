// A saved advanced credential completed from its server artifact, as its details
// open: the artifact's fields (read as saved records are read) merged into the
// record, and its registration snapshot kept as far as the sanitiser allows and
// saved back. DOM-free: both interfaces use it, each giving its own storage.
import {migrateStoredRecord} from '../../credentials/storage/local/record-migration.js';
import {sanitiseRegistrationDetailSnapshot} from '../../credentials/storage/local/snapshot-sanitize.js';

export const HYDRATE_TEXT = Object.freeze({
    failed: 'Unable to fetch credential artifact',
});

/**
 * Completes `cred` in place, once per storage id; marks it `__artifactHydrated`
 * (the storage id, 'missing' or 'error') and gives the artifact's stored
 * credential, or null. A failure is logged and changes nothing else.
 * steps: fetchCredentialArtifact(storageId), saveSnapshot(storageId, snapshot).
 */
export async function hydrateCredentialFromServer(cred, { fetchCredentialArtifact, saveSnapshot }) {
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
            void saveSnapshot(storageId, snapshot);
        }

        cred.__artifactHydrated = storageId;
        return storedCredential;
    } catch {
        // The details say so (HYDRATE_TEXT.failed), and the next opening asks again.
        cred.__artifactHydrated = 'error';
        return null;
    }
}
