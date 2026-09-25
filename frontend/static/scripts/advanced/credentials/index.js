import {state} from '../../shared/state.js';
import {
    getCredentialIdHex,
    getCredentialUserHandleHex,
    getStoredCredentialAttachment,
    normaliseAaguidValue,
} from './utils.js';
import {closeModal} from '../../shared/ui/core.js';
import {dismissAllTransientMessages} from '../../shared/ui/status.js';
import {updateJsonEditor} from '../editor/index.js';
import {checkLargeBlobCapability, updateAuthenticationExtensionAvailability} from '../auth/forms.js';
import {collectSelectedHints, deriveAllowedAttachmentsFromHints} from '../auth/hints.js';
import {ATTACHMENT_LABELS} from '../constants.js';
import {
    clearCredentialFlashQueue,
    queueAuthenticatedCredentialFlash,
    queueFailedCredentialFlash,
    readPendingCredentialFlash,
    triggerCredentialFlash,
} from '../credential-display/flash.js';
import {
    getCredentialBackgroundWarmupPromise,
    isCredentialDeletionInProgress,
    setCredentialBackgroundWarmupPromise,
    setCredentialDeletionInProgressFlag,
} from '../credential-display/state.js';
import {
    hideSharedCredentialProgress,
    showSharedCredentialProgress,
    showSharedCredentialStatus,
} from '../credential-display/shared-status.js';
import {
    loadSavedCredentialsRuntime,
    updateAllowCredentialsDropdownRuntime,
    updateCredentialsDisplayRuntime,
} from '../credential-display/list-render.js';
import {
    autoResizeCertificateTextareas,
    formatCertificateDetails,
} from '../credential-display/formatting.js';
import {
    describeCredentialAlgorithm,
    describeCredentialAlgorithmTag,
} from '../credential-display/algorithm.js';
import {deriveCredentialStatusIndicators} from '../credential-display/attestation-context.js';
import {
    handleCredentialMdsClickRuntime,
    navigateToMdsAuthenticatorRuntime,
} from '../credential-display/navigation.js';
import {
    clearAllCredentialsRuntime,
    deleteCredentialRuntime,
} from '../credential-display/deletion.js';
import {showRegistrationResultModalRuntime} from '../credential-display/registration-result.js';
import {
    closeRegistrationDetailModalRuntime,
    composeRegistrationDetail,
} from '../credential-display/registration-compose-runtime.js';
import {showCredentialDetailsRuntime} from '../credential-display/credential-detail-runtime.js';
import {
    clearSimpleCredentials as clearLocalSimpleCredentials,
    ensureAdvancedCredentialArtifactsSynced,
    ensureAdvancedCredentialSnapshotsPrefetched,
    getAllAdvancedCredentials,
    getAllSimpleCredentials,
    getAllStoredCredentialsInOrder,
    removeAdvancedCredential as removeAdvancedCredentialFromLocal,
    removeSimpleCredential as removeSimpleCredentialFromLocal,
    updateAdvancedCredentialRegistrationSnapshot,
} from '../../shared/storage/local.js';
import {sanitiseRegistrationDetailSnapshot} from '../../shared/storage/local/snapshot-sanitize.js';
import {migrateStoredRecord} from '../../shared/storage/local/record-migration.js';
import {deleteCredentialArtifact, fetchCredentialArtifact} from '../../shared/storage/artifacts-client.js';

export {queueAuthenticatedCredentialFlash, queueFailedCredentialFlash};
export {formatCertificateDetails, autoResizeCertificateTextareas};

function scheduleCredentialBackgroundWarmup() {
    if (!getCredentialBackgroundWarmupPromise()) {
        const warmupPromise = (async () => {
            const [artifactChanged, snapshotChanged] = await Promise.all([
                ensureAdvancedCredentialArtifactsSynced(),
                ensureAdvancedCredentialSnapshotsPrefetched(),
            ]);
            const changed = Boolean(artifactChanged || snapshotChanged);
            if (changed) {
                await loadSavedCredentials();
            }
            return changed;
        })()
            .catch(error => {
                console.warn('Failed to warm saved credential state', error);
                return false;
            })
            .finally(() => {
                setCredentialBackgroundWarmupPromise(null);
            });

        setCredentialBackgroundWarmupPromise(warmupPromise);
    }

    return getCredentialBackgroundWarmupPromise();
}

function setCredentialDeletionInProgress(inProgress) {
    setCredentialDeletionInProgressFlag(inProgress);
    updateCredentialsDisplay();
}

async function hydrateCredentialFromServer(cred) {
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
            void updateAdvancedCredentialRegistrationSnapshot(storageId, snapshot);
        }

        cred.__artifactHydrated = storageId;
        return storedCredential;
    } catch (error) {
        console.warn('Unable to fetch credential artifact', error);
        cred.__artifactHydrated = 'error';
        return null;
    }
}

function handleCredentialMdsClick(event) {
    handleCredentialMdsClickRuntime(event, {
        dismissAllTransientMessages,
        showSharedCredentialProgress,
        hideSharedCredentialProgress,
        showSharedCredentialStatus,
        navigateToMdsAuthenticator,
    });
}

export function closeRegistrationDetailModal() {
    closeRegistrationDetailModalRuntime();
}

export function updateAllowCredentialsDropdown() {
    updateAllowCredentialsDropdownRuntime({
        state,
        collectSelectedHints,
        deriveAllowedAttachmentsFromHints,
        getStoredCredentialAttachment,
        ATTACHMENT_LABELS,
        describeCredentialAlgorithm,
        getCredentialIdHex,
    });
}

export async function loadSavedCredentials() {
    await loadSavedCredentialsRuntime({
        getAllStoredCredentialsInOrder,
        normaliseAaguidValue,
        getCredentialIdHex,
        getCredentialUserHandleHex,
        state,
        updateCredentialsDisplay,
        updateJsonEditor,
        scheduleCredentialBackgroundWarmup,
    });
}

export function updateCredentialsDisplay() {
    updateCredentialsDisplayRuntime({
        state,
        getCredentialIdHex,
        readPendingCredentialFlash,
        isCredentialDeletionInProgress,
        checkLargeBlobCapability,
        updateAllowCredentialsDropdown,
        updateAuthenticationExtensionAvailability,
        clearCredentialFlashQueue,
        describeCredentialAlgorithmTag,
        deriveCredentialStatusIndicators,
        handleCredentialMdsClick,
        triggerCredentialFlash,
        showCredentialDetails,
        deleteCredential,
    });
}

export function navigateToMdsAuthenticator(aaguid) {
    return navigateToMdsAuthenticatorRuntime(aaguid, {
        closeCredentialModal,
    });
}

export function closeCredentialModal() {
    closeModal('credentialModal');
}

export function closeRegistrationResultModal() {
    closeModal('registrationResultModal');
}

export async function showCredentialDetails(index) {
    await showCredentialDetailsRuntime(index, {
        hydrateCredentialFromServer,
    });
}

export async function showRegistrationResultModal(credentialJson, relyingPartyInfo, options = {}) {
    await showRegistrationResultModalRuntime(credentialJson, relyingPartyInfo, options, {
        composeRegistrationDetail,
        updateAdvancedCredentialRegistrationSnapshot,
        loadSavedCredentials,
        autoResizeCertificateTextareas,
    });
}

export async function deleteCredential(index) {
    await deleteCredentialRuntime(index, {
        isCredentialDeletionInProgress,
        showSharedCredentialStatus,
        state,
        setCredentialDeletionInProgress,
        dismissAllTransientMessages,
        showSharedCredentialProgress,
        removeSimpleCredentialFromLocal,
        loadSavedCredentials,
        deleteCredentialArtifact,
        removeAdvancedCredentialFromLocal,
        hideSharedCredentialProgress,
    });
}

export async function clearAllCredentials() {
    await clearAllCredentialsRuntime({
        isCredentialDeletionInProgress,
        showSharedCredentialStatus,
        getAllSimpleCredentials,
        getAllAdvancedCredentials,
        setCredentialDeletionInProgress,
        dismissAllTransientMessages,
        showSharedCredentialProgress,
        clearLocalSimpleCredentials,
        removeAdvancedCredentialFromLocal,
        deleteCredentialArtifact,
        loadSavedCredentials,
        hideSharedCredentialProgress,
    });
}
