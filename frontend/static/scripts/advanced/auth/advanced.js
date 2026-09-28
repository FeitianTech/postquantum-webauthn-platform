import {
    ensureAuthenticationHintsAllowed,
    applyAuthenticatorAttachmentPreference,
    enforceAuthenticatorAttachmentWithHints,
} from './hints.js';
import {
    showStatus,
    hideStatus,
    showProgress,
    hideProgress
} from '../../shared/ui/status.js';
import { randomizeChallenge, randomizePrfEval, randomizeLargeBlobWrite } from './forms.js';
import { bindActions, callWith } from '../../shared/ui/actions.js';
import { randomizeUserIdentity } from '../../shared/auth/username.js';
import {
    showRegistrationResultModal,
    loadSavedCredentials,
    queueAuthenticatedCredentialFlash,
    queueFailedCredentialFlash,
    updateCredentialsDisplay,
} from '../credentials/index.js';
import { clearCeremonyResult, showCeremonyResult } from '../../shared/ui/ceremony-result.js';
import {
    saveAdvancedCredential,
    prepareAdvancedCredentialsForServer,
    updateAdvancedCredentialSignCount,
} from '../../shared/storage/local.js';
import {
    ADVANCED_CEREMONY_TEXT,
    advancedRegisteredMessage,
    advancedRegistrationFailureText,
    registerAdvancedCredential,
} from './ceremony.js';
import {
    ADVANCED_ASSERTION_TEXT,
    advancedAuthenticationFailureText,
    authenticateAdvancedCredential,
} from './assertion.js';

function maybeRandomizeAdvancedRegistrationFields() {
    const userIdInput = document.getElementById('user-id');
    const userNameInput = document.getElementById('user-name');
    if ((userIdInput && userIdInput.value.trim()) || (userNameInput && userNameInput.value.trim())) {
        randomizeUserIdentity();
    }

    const challengeRegInput = document.getElementById('challenge-reg');
    if (challengeRegInput && challengeRegInput.value.trim()) {
        randomizeChallenge('reg');
    }

    const prfFirstReg = document.getElementById('prf-eval-first-reg');
    if (prfFirstReg && prfFirstReg.value.trim()) {
        randomizePrfEval('first', 'reg');
    }

    const prfSecondReg = document.getElementById('prf-eval-second-reg');
    if (prfSecondReg && prfSecondReg.value.trim()) {
        randomizePrfEval('second', 'reg');
    }
}

function maybeRandomizeAdvancedAuthenticationFields() {
    const challengeAuthInput = document.getElementById('challenge-auth');
    if (challengeAuthInput && challengeAuthInput.value.trim()) {
        randomizeChallenge('auth');
    }

    const prfFirstAuth = document.getElementById('prf-eval-first-auth');
    if (prfFirstAuth && prfFirstAuth.value.trim()) {
        randomizePrfEval('first', 'auth');
    }

    const prfSecondAuth = document.getElementById('prf-eval-second-auth');
    if (prfSecondAuth && prfSecondAuth.value.trim()) {
        randomizePrfEval('second', 'auth');
    }

    const largeBlobWriteInput = document.getElementById('large-blob-write');
    if (largeBlobWriteInput && largeBlobWriteInput.value.trim()) {
        randomizeLargeBlobWrite();
    }
}

export async function advancedRegister() {
    let outcome = null;
    try {
        outcome = await registerAdvancedCredential(document.getElementById('json-editor').value, {
            enforceHints: enforceHintsForAdvanced,
            applyAttachmentPreference: applyAuthenticatorAttachmentPreference,
            minPinLength: () => Boolean(document.getElementById('min-pin-length')?.checked),
            fakeCredentialLength: () => parseInt(document.getElementById('fake-cred-length-reg').value) || 0,
            onStart: () => {
                hideStatus('advanced');
                clearCeremonyResult('advanced');
            },
            onProgress: text => showProgress('advanced', text),
            onWarning: text => showStatus('advanced', text, 'warning'),
            onResult: result => showCeremonyResult('advanced', result),
        });
        if (!outcome.registered) {
            showStatus('advanced', outcome.text, 'error');
            return;
        }

        const message = advancedRegisteredMessage(outcome.answer);
        showStatus('advanced', message.text, message.tone);

        maybeRandomizeAdvancedRegistrationFields();

        let savedCredentialRecord = null;
        if (outcome.record) {
            const saved = saveAdvancedCredential(outcome.record);
            if (saved) {
                savedCredentialRecord = saved;
                loadSavedCredentials();
            }
        }

        await showRegistrationResultModal(
            outcome.credentialJson,
            outcome.answer.relyingParty || null,
            {
                storageId: savedCredentialRecord?.storageId || null,
            },
        );
    } catch (error) {
        showStatus('advanced', advancedRegistrationFailureText(error, outcome ?? {}), 'error');
    } finally {
        hideProgress('advanced');
    }
}

export async function advancedAuthenticate() {
    try {
        const outcome = await authenticateAdvancedCredential(document.getElementById('json-editor').value, {
            ensureHints: ensureAuthenticationHintsAllowed,
            prepareForServer: prepareAdvancedCredentialsForServer,
            hashAlgorithm: () => document.getElementById('hash-algorithm-auth')?.value || 'SHA-256',
            fakeCredentialLength: () => parseInt(document.getElementById('fake-cred-length-auth').value) || 0,
            onStart: () => {
                hideStatus('advanced');
                clearCeremonyResult('advanced');
            },
            onProgress: text => showProgress('advanced', text),
        });
        if (!outcome.authenticated) {
            if (outcome.failedCredentialId) {
                queueFailedCredentialFlash(outcome.failedCredentialId);
                updateCredentialsDisplay();
            }
            if (outcome.result) {
                showCeremonyResult('advanced', outcome.result);
            }
            showStatus('advanced', outcome.text, 'error');
            return;
        }

        const data = outcome.answer;
        showStatus('advanced', ADVANCED_ASSERTION_TEXT.authenticated, 'success');
        showCeremonyResult('advanced', outcome.result);

        if (data.authenticatedCredentialId) {
            updateAdvancedCredentialSignCount(
                data.authenticatedCredentialId,
                typeof data.signCount === 'number' ? data.signCount : undefined,
            );
            queueAuthenticatedCredentialFlash(data.authenticatedCredentialId);
            loadSavedCredentials();
        }

        maybeRandomizeAdvancedAuthenticationFields();
    } catch (error) {
        showStatus('advanced', advancedAuthenticationFailureText(error), 'error');
    } finally {
        hideProgress('advanced');
    }
}

function enforceHintsForAdvanced(publicKey) {
    try {
        const resolved = enforceAuthenticatorAttachmentWithHints(publicKey);
        return Array.isArray(resolved) ? resolved : [];
    } catch (error) {
        showStatus('advanced', error?.message || ADVANCED_CEREMONY_TEXT.invalidHints, 'error');
        throw error;
    }
}

export const advancedActions = {
    'advanced-register': callWith(advancedRegister),
    'advanced-authenticate': callWith(advancedAuthenticate),
};

export function bindAdvancedActions() {
    return bindActions(document.getElementById('advanced-tab'), advancedActions);
}
