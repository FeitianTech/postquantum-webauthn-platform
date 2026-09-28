import {
    get,
    parseRequestOptionsFromJSON
} from '../../shared/webauthn/json-ponyfill.js';
import {
    convertExtensionsForClient,
    normalizeClientExtensionResults,
} from '../../shared/utils/binary.js';
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
import { printAuthenticationDebug } from '../../shared/debug/auth.js';
import { FailedResponseError, readFailedResponse } from '../../shared/api/failed-response.js';
import { clearCeremonyResult, showCeremonyResult } from '../../shared/ui/ceremony-result.js';
import { state } from '../../shared/state.js';
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

let advancedAuthenticateState = null;

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
        const jsonText = document.getElementById('json-editor').value;
        const parsed = JSON.parse(jsonText);

        if (!parsed.publicKey) {
            throw new Error('Invalid JSON structure: Missing "publicKey" property');
        }

        const publicKey = parsed.publicKey;

        if (!publicKey.challenge) {
            throw new Error('Invalid CredentialRequestOptions: Missing required "challenge" property');
        }

        try {
            ensureAuthenticationHintsAllowed(publicKey);
        } catch (hintError) {
            const message = hintError?.message || ADVANCED_CEREMONY_TEXT.invalidHints;
            showStatus('advanced', message, 'error');
            return;
        }

        hideStatus('advanced');
        clearCeremonyResult('advanced');
        showProgress('advanced', 'Detecting credentials...');

        const storedCredentials = prepareAdvancedCredentialsForServer();
        const requestPayload = {
            ...parsed,
            __storedCredentials: storedCredentials,
        };

        const response = await fetch('/api/advanced/authenticate/begin', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(requestPayload)
        });

        if (!response.ok) {
            const failure = await readFailedResponse(response);
            if (response.status === 404 && !failure.body?.error) {
                throw new Error('No credentials detected. Please register a credential first.');
            }
            throw new FailedResponseError(failure);
        }

        const json = await response.json();
        advancedAuthenticateState = json?.__session_state ?? null;
        const optionsJson = { ...(json || {}) };
        delete optionsJson.__session_state;
        const originalExtensions = optionsJson?.publicKey?.extensions;
        const assertOptions = parseRequestOptionsFromJSON(optionsJson);

        const convertedExtensions = convertExtensionsForClient(originalExtensions);
        if (convertedExtensions) {
            assertOptions.publicKey = assertOptions.publicKey || {};
            assertOptions.publicKey.extensions = {
                ...(assertOptions.publicKey.extensions || {}),
                ...convertedExtensions
            };
        }

        state.lastFakeCredLength = parseInt(document.getElementById('fake-cred-length-auth').value) || 0;

        showProgress('advanced', 'Connecting your authenticator device...');

        const assertion = await get(assertOptions);

        const authenticatorAttachment = assertion && typeof assertion === 'object'
            ? assertion.authenticatorAttachment ?? null
            : null;
        const assertionJson = assertion.toJSON ? assertion.toJSON() : JSON.parse(JSON.stringify(assertion));
        if (authenticatorAttachment !== undefined) {
            assertionJson.authenticatorAttachment = authenticatorAttachment;
        }
        const assertionExtensionResults = assertion.getClientExtensionResults
            ? assertion.getClientExtensionResults()
            : (assertion.clientExtensionResults || {});
        const normalizedAssertionExtensions = normalizeClientExtensionResults(assertionExtensionResults);
        const existingAssertionExtensions = assertionJson.clientExtensionResults || {};
        if (normalizedAssertionExtensions && typeof normalizedAssertionExtensions === 'object' &&
            Object.keys(normalizedAssertionExtensions).length > 0) {
            assertionJson.clientExtensionResults = {
                ...existingAssertionExtensions,
                ...normalizedAssertionExtensions,
            };
        } else if (assertionJson.clientExtensionResults === undefined) {
            assertionJson.clientExtensionResults = existingAssertionExtensions;
        }

        showProgress('advanced', 'Completing authentication...');

        const hashAlgorithm = document.getElementById('hash-algorithm-auth')?.value || 'SHA-256';

        const result = await fetch('/api/advanced/authenticate/complete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ...parsed,
                __assertion_response: assertionJson,
                __storedCredentials: storedCredentials,
                __session_state: advancedAuthenticateState,
                __hash_algorithm: hashAlgorithm,
            }),
        });

        if (result.ok) {
            const data = await result.json();

            printAuthenticationDebug(assertion, assertOptions, data);

            showStatus('advanced', 'Advanced authentication successful!', 'success');
            showCeremonyResult('advanced', {
                title: 'Last authentication',
                signCount: data.signCount,
                signCountStatus: data.signCountStatus,
                consequence: 'The advanced tab reports this and does not reject the assertion.',
                showChallenge: true,
                challengeSource: data.challengeSource,
                challengeStatus: data.challengeStatus,
            });

            if (data.authenticatedCredentialId) {
                updateAdvancedCredentialSignCount(
                    data.authenticatedCredentialId,
                    typeof data.signCount === 'number' ? data.signCount : undefined,
                );
                queueAuthenticatedCredentialFlash(data.authenticatedCredentialId);
                loadSavedCredentials();
            }

            maybeRandomizeAdvancedAuthenticationFields();
            advancedAuthenticateState = null;
        } else {
            const failure = await readFailedResponse(result);
            if (failure.failedCredentialId) {
                queueFailedCredentialFlash(failure.failedCredentialId);
                updateCredentialsDisplay();
            }
            showCeremonyResult('advanced', {
                title: 'Last authentication',
                signCountStatus: failure.signCountStatus,
                showChallenge: true,
                challengeSource: failure.challengeSource,
                challengeStatus: failure.challengeStatus,
            });
            throw new FailedResponseError(failure);
        }
    } catch (error) {
        let errorMessage = error.message;
        if (error.name === 'NotAllowedError') {
            errorMessage = 'User cancelled or no compatible authenticator detected';
        } else if (error.name === 'InvalidStateError') {
            errorMessage = 'Invalid authenticator state - please try again';
        } else if (error.name === 'SecurityError') {
            errorMessage = 'Security error - check your connection and try again';
        }

        showStatus('advanced', `Advanced authentication failed: ${errorMessage}`, 'error');
    } finally {
        hideProgress('advanced');
        advancedAuthenticateState = null;
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
