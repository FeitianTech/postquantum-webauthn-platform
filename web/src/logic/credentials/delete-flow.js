// Deleting a saved credential, and all of them: in what order, and what each
// outcome says. DOM-free. The list asks the person in a dialog first, and its
// report says where messages and progress go. Each credential gone from this
// browser is signalled to the browser itself (./deletion-signal.js).
import { SIGNAL_TEXT, canSignalDeletion, signalDeletedCredential } from './deletion-signal.js';
import { deleteCredentialArtifact } from './storage/artifacts-client.js';
import { getAllAdvancedCredentials, removeAdvancedCredential } from './storage/local/advanced-credentials.js';
import { getAllSimpleCredentials, removeSimpleCredential, simpleUsername } from './storage/local/simple-credentials.js';
import { deleteSimpleCredentialRecord } from './storage/simple-records-client.js';

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
 * The question before deleting one credential, naming whose it is, and saying so
 * where the browser will be told it is gone.
 * @param {Record<string, any>} credential
 * @param {any} [scope]
 * @returns {string}
 */
export function deleteConfirmation(credential, scope = globalThis) {
    const label = credential.userName || credential.username || credential.email || 'this credential';
    const question = `Are you sure you want to delete the credential for ${label}? This action cannot be undone.`;
    return canSignalDeletion(scope) ? `${question} ${SIGNAL_TEXT.one}` : question;
}

export const CLEAR_ALL_CONFIRMATION = 'Are you sure you want to delete all saved credentials? This action cannot be undone.';

/**
 * The question before deleting every saved credential, saying so where the
 * browser will be told they are gone.
 * @param {any} [scope]
 * @returns {string}
 */
export function clearAllConfirmation(scope = globalThis) {
    return canSignalDeletion(scope) ? `${CLEAR_ALL_CONFIRMATION} ${SIGNAL_TEXT.all}` : CLEAR_ALL_CONFIRMATION;
}

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
 * What one deletion came to: 'deleted', 'absent' (the server no longer had its
 * copy), or 'failed' with the sentence that says why.
 * @typedef {{ status: string, error: string }} DeletionOutcome
 */

// The outcomes that leave a credential gone: what the list reports as deleted.
const GONE = ['deleted', 'absent'];

/**
 * Where a saved credential is kept: the server's copy when it has one (an advanced
 * credential's artifact, a simple one's record under its username), and this
 * browser's.
 * @param {Record<string, any>} credential
 * @returns {{ onServer: (() => Promise<{ status: string, error?: string }>) | null, here: () => boolean }}
 */
function whereKept(credential) {
    const identifier = credential.credentialIdBase64Url || credential.credentialId || credential.id;
    if (credential.type === 'simple') {
        const username = credential.email || credential.userName || credential.username;
        return {
            onServer: identifier && simpleUsername(username) ? () => deleteSimpleCredentialRecord(identifier, username) : null,
            here: () => removeSimpleCredential(identifier, username),
        };
    }
    const storageId = credential.storageId || credential.localStorageId;
    const kept = typeof storageId === 'string' && storageId.trim() ? storageId.trim() : null;
    return {
        onServer: kept ? () => deleteCredentialArtifact(kept) : null,
        here: () => removeAdvancedCredential(identifier, kept),
    };
}

/**
 * Deletes one saved credential where it is kept: from the server's storage first,
 * when it keeps a copy, then from this browser; once it is gone, the browser is
 * told (without waiting for it).
 * @param {Record<string, any>} credential
 * @param {any} scope
 * @returns {Promise<DeletionOutcome>}
 */
async function deleteEverywhere(credential, scope) {
    const { onServer, here } = whereKept(credential);
    const answer = onServer ? await onServer() : { status: 'deleted' };
    if (answer.status === 'failed') {
        return { status: 'failed', error: answer.error || DELETE_TEXT.serverRefused };
    }
    if (!here()) {
        return { status: 'failed', error: onServer ? DELETE_TEXT.removedFromServerOnly : DELETE_TEXT.notRemovedLocally };
    }
    if (GONE.includes(answer.status)) {
        void signalDeletedCredential(credential, scope);
    }
    return { status: answer.status, error: '' };
}

/**
 * Deletes one saved credential, from the server's storage first when it keeps a
 * copy (both tabs' credentials do), then from this browser.
 * @param {Record<string, any> | null | undefined} credential
 * @param {DeletionReport} report
 * @param {any} [scope] the page's global, which the browser is told through
 * @returns {Promise<void>}
 */
export async function deleteSavedCredential(credential, report, scope = globalThis) {
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

    try {
        const outcome = await deleteEverywhere(credential, scope);
        if (outcome.status === 'failed') {
            report.status(outcome.error, 'error');
            return;
        }

        await report.reload();
        if (outcome.status === 'absent') {
            report.status(DELETE_TEXT.alreadyAbsent, 'warning');
            return;
        }
        report.status(DELETE_TEXT.deleted, 'success');
    } finally {
        report.progress(null);
        report.setRunning(false);
    }
}

/**
 * Deletes saved credentials, each where it is kept. A username's simple ones are
 * one list on the server, which each deletion rewrites by compare-and-swap, so
 * they go one at a time; other usernames' and the advanced ones go at once.
 * @param {Record<string, any>[]} simpleCredentials
 * @param {Array<Record<string, any> | null>} advancedCredentials
 * @param {any} scope
 * @returns {Promise<DeletionOutcome[]>}
 */
async function deleteAll(simpleCredentials, advancedCredentials, scope) {
    /** @type {Map<string, Record<string, any>[]>} */
    const byUsername = new Map();
    simpleCredentials.forEach(credential => {
        const username = simpleUsername(credential.email || credential.userName || credential.username);
        byUsername.set(username, [...(byUsername.get(username) || []), credential]);
    });
    const inTurn = async credentials => {
        const outcomes = [];
        for (const credential of credentials) {
            outcomes.push(await deleteEverywhere(credential, scope));
        }
        return outcomes;
    };
    const outcomes = await Promise.all([
        ...[...byUsername.values()].map(inTurn),
        ...advancedCredentials.map(credential => inTurn([credential || {}])),
    ]);
    return outcomes.flat();
}

/**
 * Deletes every saved credential, each from the server's storage first when it
 * keeps a copy, then from this browser.
 * @param {DeletionReport} report
 * @param {any} [scope] the page's global, which the browser is told through
 * @returns {Promise<void>}
 */
export async function clearSavedCredentials(report, scope = globalThis) {
    if (report.isRunning()) {
        report.status(DELETE_TEXT.inProgress, 'info');
        return;
    }

    const simpleCredentials = getAllSimpleCredentials();
    const advancedCredentials = getAllAdvancedCredentials();
    if (simpleCredentials.length === 0 && advancedCredentials.length === 0) {
        report.status(DELETE_TEXT.nothingToClear, 'info');
        return;
    }

    report.setRunning(true);
    report.dismiss();
    report.progress(DELETE_TEXT.clearing);

    try {
        const outcomes = await deleteAll(simpleCredentials, advancedCredentials, scope);
        const absentCount = outcomes.filter(outcome => outcome.status === 'absent').length;
        const failedCount = outcomes.filter(outcome => !GONE.includes(outcome.status)).length;

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
