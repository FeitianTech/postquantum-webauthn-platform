export async function deleteCredentialRuntime(index, deps) {
    const {
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
    } = deps;

    if (isCredentialDeletionInProgress()) {
        showSharedCredentialStatus('A credential deletion is already in progress.', 'info');
        return;
    }

    const credential = state.storedCredentials[index];
    if (!credential) {
        return;
    }

    const label = credential.userName || credential.username || credential.email || 'this credential';
    if (!confirm(`Are you sure you want to delete the credential for ${label}? This action cannot be undone.`)) {
        return;
    }

    setCredentialDeletionInProgress(true);
    dismissAllTransientMessages();
    showSharedCredentialProgress('Deleting credential...');

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
                showSharedCredentialStatus('Deletion successful.', 'success');
            } else {
                showSharedCredentialStatus('Unable to remove credential from this browser.', 'error');
            }
            return;
        }

        if (storageId) {
            const deleteResult = await deleteCredentialArtifact(storageId);
            if (deleteResult.status === 'failed') {
                showSharedCredentialStatus(
                    deleteResult.error || 'Unable to delete credential from server storage.',
                    'error',
                );
                return;
            }

            const removedAdvanced = removeAdvancedCredentialFromLocal(identifier, storageId);
            if (!removedAdvanced) {
                showSharedCredentialStatus('Credential was deleted from server but could not be removed locally.', 'error');
                return;
            }

            await loadSavedCredentials();
            if (deleteResult.status === 'absent') {
                showSharedCredentialStatus('Credential was already absent from server storage and has been removed locally.', 'warning');
                return;
            }

            showSharedCredentialStatus('Deletion successful.', 'success');
            return;
        }

        const removedAdvanced = removeAdvancedCredentialFromLocal(identifier, storageId);
        if (!removedAdvanced) {
            showSharedCredentialStatus('Unable to remove credential from this browser.', 'error');
            return;
        }

        await loadSavedCredentials();
        showSharedCredentialStatus('Deletion successful.', 'success');
    } finally {
        hideSharedCredentialProgress();
        setCredentialDeletionInProgress(false);
    }
}

export async function clearAllCredentialsRuntime(deps) {
    const {
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
    } = deps;

    if (isCredentialDeletionInProgress()) {
        showSharedCredentialStatus('A credential deletion is already in progress.', 'info');
        return;
    }

    const simpleCredentials = getAllSimpleCredentials();
    const advancedCredentials = getAllAdvancedCredentials();

    const simpleCount = simpleCredentials.length;
    const advancedCount = advancedCredentials.length;

    if (simpleCount === 0 && advancedCount === 0) {
        showSharedCredentialStatus('No saved credentials to clear.', 'info');
        return;
    }

    if (!confirm('Are you sure you want to delete all saved credentials? This action cannot be undone.')) {
        return;
    }

    setCredentialDeletionInProgress(true);
    dismissAllTransientMessages();
    showSharedCredentialProgress('Clearing all credentials...');

    let deletedCount = 0;
    let absentCount = 0;
    let failedCount = 0;

    try {
        if (simpleCount > 0) {
            clearLocalSimpleCredentials();
            deletedCount += simpleCount;
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
                    error: deleteResult.error || 'Unable to delete credential from server storage.',
                };
            }

            const removedLocal = removeAdvancedCredentialFromLocal(identifier, storageId.trim());
            if (!removedLocal) {
                return {
                    status: 'failed',
                    error: 'Credential was deleted from server but could not be removed locally.',
                };
            }

            return {
                status: deleteResult.status,
            };
        });

        const advancedResults = await Promise.all(advancedDeleteOperations);
        advancedResults.forEach(result => {
            if (result.status === 'deleted') {
                deletedCount += 1;
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
            const noun = failedCount === 1 ? 'credential' : 'credentials';
            const verb = failedCount === 1 ? 'was' : 'were';
            showSharedCredentialStatus(
                `Clearing completed with issues: ${failedCount} ${noun} could not be deleted from server storage and ${verb} kept.`,
                'error',
            );
            return;
        }

        if (absentCount > 0) {
            const noun = absentCount === 1 ? 'credential was' : 'credentials were';
            showSharedCredentialStatus(
                `Clearing complete. ${absentCount} ${noun} already absent from server storage.`,
                'warning',
            );
            return;
        }

        if (deletedCount > 0) {
            showSharedCredentialStatus('Deletion successful.', 'success');
            return;
        }

        showSharedCredentialStatus('No saved credentials to clear.', 'info');
    } catch (error) {
        console.error('Failed to clear saved credentials.', error);
        showSharedCredentialStatus('Failed to clear all credentials. Please try again.', 'error');
    } finally {
        hideSharedCredentialProgress();
        setCredentialDeletionInProgress(false);
    }
}
