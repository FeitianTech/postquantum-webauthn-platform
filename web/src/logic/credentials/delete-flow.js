// Deleting a saved credential, and all of them: in what order, and what each
// outcome says. DOM-free. The list asks the person in a dialog first, and its
// report says where messages and progress go.
import { deleteCredentialArtifact } from './storage/artifacts-client.js';
import { getAllAdvancedCredentials, removeAdvancedCredential } from './storage/local/advanced-credentials.js';
import { clearSimpleCredentials, getAllSimpleCredentials, removeSimpleCredential } from './storage/local/simple-credentials.js';

/**
 * A message of the list's: a success is a toast, the rest stay under the header.
 * @typedef {'success' | 'error' | 'warning' | 'info'} ListTone
 */

/**
 * Where a deletion's steps report, and whether one is running.
 * @typedef {object} DeletionReport
 * @property {() => boolean} isRunning
 * @property {(running: boolean) => void} setRunning
 * @property {() => void} dismiss
 * @property {(text: string | null) => void} progress
 * @property {(text: string, tone: ListTone) => void} status
 * @property {() => Promise<void>} reload
 */

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

/**
 * The question before deleting one credential, naming whose it is.
 * @param {Record<string, any>} credential
 * @returns {string}
 */
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
 * @param {Record<string, any> | null | undefined} credential
 * @param {DeletionReport} report
 * @returns {Promise<void>}
 */
export async function deleteSavedCredential(credential, report) {
    if (report.isRunning()) {
        report.status(DELETE_TEXT.inProgress, 'info');
        return;
    }

    if (!credential) {
        return;
    }

    report.setRunning(true);
    report.dismiss();
    report.progress(DELETE_TEXT.deleting);

    const identifier = credential.credentialIdBase64Url || credential.credentialId || credential.id;
    const storageId = credential.storageId || credential.localStorageId || null;

    try {
        if (credential.type === 'simple') {
            const removed = removeSimpleCredential(
                identifier,
                credential.email || credential.userName || credential.username,
            );
            if (removed) {
                await report.reload();
                report.status(DELETE_TEXT.deleted, 'success');
            } else {
                report.status(DELETE_TEXT.notRemovedLocally, 'error');
            }
            return;
        }

        if (storageId) {
            const deleteResult = await deleteCredentialArtifact(storageId);
            if (deleteResult.status === 'failed') {
                report.status(deleteResult.error || DELETE_TEXT.serverRefused, 'error');
                return;
            }

            const removedAdvanced = removeAdvancedCredential(identifier, storageId);
            if (!removedAdvanced) {
                report.status(DELETE_TEXT.removedFromServerOnly, 'error');
                return;
            }

            await report.reload();
            if (deleteResult.status === 'absent') {
                report.status(DELETE_TEXT.alreadyAbsent, 'warning');
                return;
            }

            report.status(DELETE_TEXT.deleted, 'success');
            return;
        }

        const removedAdvanced = removeAdvancedCredential(identifier, storageId);
        if (!removedAdvanced) {
            report.status(DELETE_TEXT.notRemovedLocally, 'error');
            return;
        }

        await report.reload();
        report.status(DELETE_TEXT.deleted, 'success');
    } finally {
        report.progress(null);
        report.setRunning(false);
    }
}

/**
 * Deletes every saved credential: the simple ones from this browser, each
 * advanced one from the server's storage and then from this browser.
 * @param {DeletionReport} report
 * @returns {Promise<void>}
 */
export async function clearSavedCredentials(report) {
    if (report.isRunning()) {
        report.status(DELETE_TEXT.inProgress, 'info');
        return;
    }

    const simpleCredentials = getAllSimpleCredentials();
    const advancedCredentials = getAllAdvancedCredentials();

    const simpleCount = simpleCredentials.length;
    const advancedCount = advancedCredentials.length;

    if (simpleCount === 0 && advancedCount === 0) {
        report.status(DELETE_TEXT.nothingToClear, 'info');
        return;
    }

    report.setRunning(true);
    report.dismiss();
    report.progress(DELETE_TEXT.clearing);

    let absentCount = 0;
    let failedCount = 0;

    try {
        if (simpleCount > 0) {
            clearSimpleCredentials();
        }

        const advancedDeleteOperations = advancedCredentials.map(async credential => {
            const identifier = credential?.credentialIdBase64Url || credential?.credentialId || credential?.id;
            const storageId = (credential && typeof credential === 'object' && (credential.storageId || credential.localStorageId)) || null;

            if (!storageId || typeof storageId !== 'string' || !storageId.trim()) {
                const removedLocal = removeAdvancedCredential(identifier, null);
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

            const removedLocal = removeAdvancedCredential(identifier, storageId.trim());
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

        await report.reload();

        if (failedCount > 0) {
            report.status(clearingWithIssues(failedCount), 'error');
            return;
        }

        if (absentCount > 0) {
            report.status(clearedWithAbsent(absentCount), 'warning');
            return;
        }

        // Something was saved (else the flow ended above), and none failed or was absent.
        report.status(DELETE_TEXT.deleted, 'success');
    } catch {
        report.status(DELETE_TEXT.clearFailed, 'error');
    } finally {
        report.progress(null);
        report.setRunning(false);
    }
}
