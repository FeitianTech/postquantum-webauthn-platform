import {state} from '../../shared/state.js';
import {
    getCredentialIdHex,
    getCredentialUserHandleHex,
    getStoredCredentialAttachment,
    normaliseAaguidValue,
} from './utils.js';
import {bindActions, callWith} from '../../shared/ui/actions.js';
import {closeModal} from '../../shared/ui/core.js';
import {dismissAllTransientMessages} from '../../shared/ui/status.js';
import {updateJsonEditor} from '../editor/index.js';
import {checkLargeBlobCapability, updateAuthenticationExtensionAvailability} from '../auth/forms.js';
import {collectSelectedHints, deriveAllowedAttachmentsFromHints} from '../auth/hints.js';
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
import {hydrateCredentialFromServer as hydrateCredential} from './hydrate.js';
import {warmSavedCredentials} from './saved-list.js';
import {
    closeRegistrationDetailModalRuntime,
    composeRegistrationDetail,
} from '../credential-display/registration-compose-runtime.js';
import {showCredentialDetailsRuntime} from '../credential-display/credential-detail-runtime.js';
import {
    clearSimpleCredentials as clearLocalSimpleCredentials,
    ensureAdvancedCredentialArtifactsSynced,
    ensureAdvancedCredentialSnapshotsPrefetched,
    followStoredCredentialChanges,
    getAllAdvancedCredentials,
    getAllSimpleCredentials,
    getAllStoredCredentialsInOrder,
    removeAdvancedCredential as removeAdvancedCredentialFromLocal,
    removeSimpleCredential as removeSimpleCredentialFromLocal,
    updateAdvancedCredentialRegistrationSnapshot,
} from '../../shared/storage/local.js';
import {deleteCredentialArtifact, fetchCredentialArtifact} from '../../shared/storage/artifacts-client.js';

export {queueAuthenticatedCredentialFlash, queueFailedCredentialFlash};
export {formatCertificateDetails, autoResizeCertificateTextareas};

function scheduleCredentialBackgroundWarmup() {
    if (!getCredentialBackgroundWarmupPromise()) {
        const warmupPromise = warmSavedCredentials({
            syncArtifacts: ensureAdvancedCredentialArtifactsSynced,
            prefetchSnapshots: ensureAdvancedCredentialSnapshotsPrefetched,
            reload: loadSavedCredentials,
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

// Completes an advanced record from its server artifact (./hydrate.js), saving
// its snapshot through this interface's storage.
function hydrateCredentialFromServer(cred) {
    return hydrateCredential(cred, {
        fetchCredentialArtifact,
        saveSnapshot: updateAdvancedCredentialRegistrationSnapshot,
    });
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

// The explorer's side of "show this authenticator": switchTab, highlightRow,
// resolveEntry, finaliseHighlight. main.js sets it; until then the credential
// view says the integration is unavailable.
let mdsNavigation = {};

export function setMdsNavigation(navigation) {
    mdsNavigation = navigation && typeof navigation === 'object' ? { ...navigation } : {};
}

export function navigateToMdsAuthenticator(aaguid) {
    return navigateToMdsAuthenticatorRuntime(aaguid, {
        ...mdsNavigation,
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

export const credentialActions = {
    'clear-all-credentials': callWith(clearAllCredentials),
    'close-credential-modal': callWith(closeCredentialModal),
    'close-registration-result-modal': callWith(closeRegistrationResultModal),
    'close-registration-detail-modal': callWith(closeRegistrationDetailModal),
};

// On the document: both tabs have a Clear All button, and the modals sit outside them.
// A change another tab makes to the saved credentials is drawn here too.
export function bindCredentialActions() {
    followStoredCredentialChanges(loadSavedCredentials);
    return bindActions(document, credentialActions);
}
