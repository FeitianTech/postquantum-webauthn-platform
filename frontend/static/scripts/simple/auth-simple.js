import { FailedResponseError } from '../shared/api/failed-response.js';
import { clearCeremonyResult, showCeremonyResult } from '../shared/ui/ceremony-result.js';
import { showStatus, hideStatus, showProgress, hideProgress } from '../shared/ui/status.js';
import {
    loadSavedCredentials,
    queueAuthenticatedCredentialFlash,
    queueFailedCredentialFlash,
    updateCredentialsDisplay,
} from '../advanced/credentials/index.js';
import { bindActions, callWith } from '../shared/ui/actions.js';
import {
    getSimpleCredentialsForEmail,
    saveSimpleCredential,
    prepareCredentialsForServer,
    updateSimpleCredentialSignCount,
} from '../shared/storage/local.js';
import {
    SIMPLE_CEREMONY_TEXT,
    authenticateSimplePasskey,
    ceremonyErrorText,
    registerSimplePasskey,
    registeredText,
} from './ceremony.js';

// The Simple tab's view: the username field, the toast, the progress bar, the
// result panel and the saved credentials. The ceremonies are ./ceremony.js's.

const showSimpleProgress = text => showProgress('simple', text);

export async function simpleRegister() {
    const email = document.getElementById('simple-email').value;
    if (!email) {
        showStatus('simple', SIMPLE_CEREMONY_TEXT.usernameRequired, 'error');
        return;
    }

    try {
        hideStatus('simple');
        clearCeremonyResult('simple');

        const data = await registerSimplePasskey(email, { onProgress: showSimpleProgress });
        showStatus('simple', registeredText(data), 'success');

        if (data.storedCredential && typeof data.storedCredential === 'object') {
            saveSimpleCredential({ ...data.storedCredential, email });
            loadSavedCredentials();
        }

        setTimeout(loadSavedCredentials, 1000);
    } catch (error) {
        showStatus('simple', ceremonyErrorText(error, 'registration'), 'error');
    } finally {
        hideProgress('simple');
    }
}

export async function simpleAuthenticate() {
    const email = document.getElementById('simple-email').value;
    if (!email) {
        showStatus('simple', SIMPLE_CEREMONY_TEXT.usernameRequired, 'error');
        return;
    }

    try {
        hideStatus('simple');
        clearCeremonyResult('simple');

        const outcome = await authenticateSimplePasskey(email, {
            credentialsFor: getSimpleCredentialsForEmail,
            prepareForServer: prepareCredentialsForServer,
            onProgress: showSimpleProgress,
        });

        if (outcome.failure) {
            if (outcome.failure.failedCredentialId) {
                queueFailedCredentialFlash(outcome.failure.failedCredentialId);
                updateCredentialsDisplay();
            }
            showCeremonyResult('simple', outcome.result);
            throw new FailedResponseError(outcome.failure);
        }

        const data = outcome.answer;
        showStatus('simple', SIMPLE_CEREMONY_TEXT.authenticated, 'success');
        showCeremonyResult('simple', outcome.result);

        if (data.authenticatedCredentialId) {
            updateSimpleCredentialSignCount(
                email,
                data.authenticatedCredentialId,
                typeof data.signCount === 'number' ? data.signCount : undefined
            );
            queueAuthenticatedCredentialFlash(data.authenticatedCredentialId);
            loadSavedCredentials();
        }
    } catch (error) {
        showStatus('simple', ceremonyErrorText(error, 'authentication'), 'error');
    } finally {
        hideProgress('simple');
    }
}

export const simpleActions = {
    'simple-register': callWith(simpleRegister),
    'simple-authenticate': callWith(simpleAuthenticate),
};

export function bindSimpleActions() {
    return bindActions(document.getElementById('simple-tab'), simpleActions);
}
