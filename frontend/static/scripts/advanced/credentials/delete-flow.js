// Deleting a saved credential, and all of them: what is asked, in what order,
// and what each outcome says. DOM-free. The storage and server functions, the
// question to the person, and where messages and progress go are passed in: the
// current UI asks with the browser's confirm and shows toasts in both tabs; the
// new UI asks in a dialog first and shows its own.

export const DELETE_TEXT = {
    inProgress: 'A credential deletion is already in progress.',
    deleting: 'Deleting credential...',
    deleted: 'Deletion successful.',
    notRemovedLocally: 'Unable to remove credential from this browser.',
    serverRefused: 'Unable to delete credential from server storage.',
    removedFromServerOnly: 'Credential was deleted from server but could not be removed locally.',
    alreadyAbsent: 'Credential was already absent from server storage and has been removed locally.',
    nothingToClear: 'No saved credentials to clear.',
    clearing: 'Clearing all credentials...',
    clearFailed: 'Failed to clear all credentials. Please try again.',
};

/** The question before deleting one credential, naming whose it is. */
export function deleteConfirmation(credential) {
    const label = credential.userName || credential.username || credential.email || 'this credential';
    return `Are you sure you want to delete the credential for ${label}? This action cannot be undone.`;
}

export const CLEAR_ALL_CONFIRMATION = 'Are you sure you want to delete all saved credentials? This action cannot be undone.';

function clearingWithIssues(failedCount) {
    const noun = failedCount === 1 ? 'credential' : 'credentials';
    const verb = failedCount === 1 ? 'was' : 'were';
    return `Clearing completed with issues: ${failedCount} ${noun} could not be deleted from server storage and ${verb} kept.`;
}

function clearedWithAbsent(absentCount) {
    const noun = absentCount === 1 ? 'credential was' : 'credentials were';
    return `Clearing complete. ${absentCount} ${noun} already absent from server storage.`;
}

/**
 * Deletes one saved credential: a simple one from this browser, an advanced one
 * from the server's storage and then from this browser.
 *
 * deps: isCredentialDeletionInProgress, confirm(question) → boolean,
 * setCredentialDeletionInProgress, dismissAllTransientMessages,
 * showSharedCredentialProgress, hideSharedCredentialProgress,
 * showSharedCredentialStatus(message, tone), removeSimpleCredentialFromLocal,
 * removeAdvancedCredentialFromLocal, deleteCredentialArtifact, loadSavedCredentials.
 */
export async function deleteSavedCredential(credential, deps) {
    const {
        isCredentialDeletionInProgress,
        confirm,
        showSharedCredentialStatus,
        setCredentialDeletionInProgress,
        dismissAllTransientMessages,
        showSharedCredentialProgress,
        removeSimpleCredentialFromLocal,
        loadSavedCredentials,
        deleteCredentialArtifact,
        removeAdvancedCredentialFromLocal,
        hideSharedCredentialProgress,
    } = deps;

    if (isCredentialDeletionInProgress()) {
        showSharedCredentialStatus(DELETE_TEXT.inProgress, 'info');
        return;
    }

    if (!credential) {
        return;
    }

    if (!confirm(deleteConfirmation(credential))) {
        return;
    }

    setCredentialDeletionInProgress(true);
    dismissAllTransientMessages();
    showSharedCredentialProgress(DELETE_TEXT.deleting);

    const identifier = credential.credentialIdBase64Url || credential.credentialId || credential.id;
    const storageId = credential.storageId || credential.localStorageId || null;

    try {
        if (credential.type === 'simple') {
            const removed = removeSimpleCredentialFromLocal(
                identifier,
                credential.email || credential.userName || credential.username,
            );
            if (removed) {
                await loadSavedCredentials();
                showSharedCredentialStatus(DELETE_TEXT.deleted, 'success');
            } else {
                showSharedCredentialStatus(DELETE_TEXT.notRemovedLocally, 'error');
            }
            return;
        }

        if (storageId) {
            const deleteResult = await deleteCredentialArtifact(storageId);
            if (deleteResult.status === 'failed') {
                showSharedCredentialStatus(deleteResult.error || DELETE_TEXT.serverRefused, 'error');
                return;
            }

            const removedAdvanced = removeAdvancedCredentialFromLocal(identifier, storageId);
            if (!removedAdvanced) {
                showSharedCredentialStatus(DELETE_TEXT.removedFromServerOnly, 'error');
                return;
            }

            await loadSavedCredentials();
            if (deleteResult.status === 'absent') {
                showSharedCredentialStatus(DELETE_TEXT.alreadyAbsent, 'warning');
                return;
            }

            showSharedCredentialStatus(DELETE_TEXT.deleted, 'success');
            return;
        }

        const removedAdvanced = removeAdvancedCredentialFromLocal(identifier, storageId);
        if (!removedAdvanced) {
            showSharedCredentialStatus(DELETE_TEXT.notRemovedLocally, 'error');
            return;
        }

        await loadSavedCredentials();
        showSharedCredentialStatus(DELETE_TEXT.deleted, 'success');
    } finally {
        hideSharedCredentialProgress();
        setCredentialDeletionInProgress(false);
    }
}

/**
 * Deletes every saved credential: the simple ones from this browser, each
 * advanced one from the server's storage and then from this browser.
 *
 * deps: as deleteSavedCredential's, with getAllSimpleCredentials,
 * getAllAdvancedCredentials and clearLocalSimpleCredentials in place of
 * removeSimpleCredentialFromLocal.
 */
export async function clearSavedCredentials(deps) {
    const {
        isCredentialDeletionInProgress,
        confirm,
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
    } = deps;

    if (isCredentialDeletionInProgress()) {
        showSharedCredentialStatus(DELETE_TEXT.inProgress, 'info');
        return;
    }

    const simpleCredentials = getAllSimpleCredentials();
    const advancedCredentials = getAllAdvancedCredentials();

    const simpleCount = simpleCredentials.length;
    const advancedCount = advancedCredentials.length;

    if (simpleCount === 0 && advancedCount === 0) {
        showSharedCredentialStatus(DELETE_TEXT.nothingToClear, 'info');
        return;
    }

    if (!confirm(CLEAR_ALL_CONFIRMATION)) {
        return;
    }

    setCredentialDeletionInProgress(true);
    dismissAllTransientMessages();
    showSharedCredentialProgress(DELETE_TEXT.clearing);

    let absentCount = 0;
    let failedCount = 0;

    try {
        if (simpleCount > 0) {
            clearLocalSimpleCredentials();
        }

        const advancedDeleteOperations = advancedCredentials.map(async credential => {
            const identifier = credential?.credentialIdBase64Url || credential?.credentialId || credential?.id;
            const storageId = (credential && typeof credential === 'object' && (credential.storageId || credential.localStorageId)) || null;

            if (!storageId || typeof storageId !== 'string' || !storageId.trim()) {
                const removedLocal = removeAdvancedCredentialFromLocal(identifier, null);
                return {
                    status: removedLocal ? 'deleted' : 'failed',
                };
            }

            const deleteResult = await deleteCredentialArtifact(storageId.trim());
            if (deleteResult.status === 'failed') {
                return {
                    status: 'failed',
                    error: deleteResult.error || DELETE_TEXT.serverRefused,
                };
            }

            const removedLocal = removeAdvancedCredentialFromLocal(identifier, storageId.trim());
            if (!removedLocal) {
                return {
                    status: 'failed',
                    error: DELETE_TEXT.removedFromServerOnly,
                };
            }

            return {
                status: deleteResult.status,
            };
        });

        const advancedResults = await Promise.all(advancedDeleteOperations);
        advancedResults.forEach(result => {
            if (result.status === 'deleted') {
                return;
            }
            if (result.status === 'absent') {
                absentCount += 1;
                return;
            }
            failedCount += 1;
        });

        await loadSavedCredentials();

        if (failedCount > 0) {
            showSharedCredentialStatus(clearingWithIssues(failedCount), 'error');
            return;
        }

        if (absentCount > 0) {
            showSharedCredentialStatus(clearedWithAbsent(absentCount), 'warning');
            return;
        }

        // Something was saved (else the flow ended above), and none failed or was absent.
        showSharedCredentialStatus(DELETE_TEXT.deleted, 'success');
    } catch (error) {
        console.error('Failed to clear saved credentials.', error);
        showSharedCredentialStatus(DELETE_TEXT.clearFailed, 'error');
    } finally {
        hideSharedCredentialProgress();
        setCredentialDeletionInProgress(false);
    }
}
