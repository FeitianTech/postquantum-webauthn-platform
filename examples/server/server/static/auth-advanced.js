import {
    create,
    get,
    parseCreationOptionsFromJSON,
    parseRequestOptionsFromJSON
} from './webauthn-json.browser-ponyfill.js';
import {
    convertExtensionsForClient,
    normalizeClientExtensionResults
} from './binary-utils.js';
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
} from './status.js';
import { updateJsonEditor, getAdvancedCreateOptions, getAdvancedAssertOptions } from './json-editor.js';
import { randomizeChallenge, randomizePrfEval, randomizeLargeBlobWrite } from './forms.js';
import { randomizeUserIdentity } from './username.js';
import { showRegistrationResultModal, loadSavedCredentials } from './credential-display.js';
import { printRegistrationDebug, printAuthenticationDebug } from './auth-debug.js';
import { state } from './state.js';

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

const COMMON_SUPPORTED_ALGORITHMS = new Set([-7, -257, -8]);

function collectPotentialUnsupportedFeatures(publicKeyOptions, convertedExtensions, createOptions) {
    const issues = [];

    if (!publicKeyOptions || typeof publicKeyOptions !== 'object') {
        return issues;
    }

    const selection = publicKeyOptions.authenticatorSelection && typeof publicKeyOptions.authenticatorSelection === 'object'
        ? publicKeyOptions.authenticatorSelection
        : {};

    if (selection.requireResidentKey === true || selection.residentKey === 'required') {
        issues.push('resident key requirement');
    }
    if (selection.userVerification === 'required') {
        issues.push('user verification requirement');
    }

    const extensionSources = [];
    if (publicKeyOptions.extensions && typeof publicKeyOptions.extensions === 'object') {
        extensionSources.push(publicKeyOptions.extensions);
    }
    if (convertedExtensions && typeof convertedExtensions === 'object') {
        extensionSources.push(convertedExtensions);
    }

    const extensionLabels = [
        ['largeBlob', 'largeBlob extension'],
        ['prf', 'prf extension'],
        ['minPinLength', 'minPinLength extension'],
        ['credentialProtectionPolicy', 'credProtect extension'],
        ['credProps', 'credProps extension'],
    ];

    extensionSources.forEach(source => {
        extensionLabels.forEach(([key, label]) => {
            if (source && Object.prototype.hasOwnProperty.call(source, key) && !issues.includes(label)) {
                issues.push(label);
            }
        });
    });

    const pubKeyOptions = createOptions && typeof createOptions === 'object' && createOptions.publicKey && typeof createOptions.publicKey === 'object'
        ? createOptions.publicKey
        : null;
    const params = pubKeyOptions && Array.isArray(pubKeyOptions.pubKeyCredParams)
        ? pubKeyOptions.pubKeyCredParams
        : [];

    if (params.length) {
        const algValues = params
            .map(param => (param && typeof param === 'object' ? param.alg : undefined))
            .filter(value => typeof value === 'number');
        if (algValues.length) {
            const hasCommon = algValues.some(value => COMMON_SUPPORTED_ALGORITHMS.has(value));
            if (!hasCommon) {
                issues.push('selected signature algorithms');
            }
        }
    }

    return issues;
}

export async function advancedRegister() {
    let publicKey = null;
    let allowedAttachments = [];
    let convertedExtensions = null;
    let createOptions = null;

    try {
        const jsonText = document.getElementById('json-editor').value;
        const parsed = JSON.parse(jsonText);

        if (!parsed.publicKey) {
            throw new Error('Invalid JSON structure: Missing "publicKey" property');
        }

        publicKey = parsed.publicKey;

        if (!publicKey.rp) {
            throw new Error('Invalid CredentialCreationOptions: Missing required "rp" property');
        }
        if (!publicKey.user) {
            throw new Error('Invalid CredentialCreationOptions: Missing required "user" property');
        }
        if (!publicKey.challenge) {
            throw new Error('Invalid CredentialCreationOptions: Missing required "challenge" property');
        }

        if (document.getElementById('min-pin-length')?.checked) {
            if (!publicKey.extensions || typeof publicKey.extensions !== 'object') {
                publicKey.extensions = {};
            }
            publicKey.extensions.minPinLength = true;
        }

        allowedAttachments = enforceHintsForAdvanced(publicKey);

        hideStatus('advanced');
        showProgress('advanced', 'Starting advanced registration...');

        const response = await fetch('/api/advanced/register/begin', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(parsed)
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server error: ${errorText}`);
        }

        const json = await response.json();

        const warnings = Array.isArray(json?.warnings)
            ? json.warnings.filter((msg) => typeof msg === 'string' && msg.trim().length > 0)
            : [];
        if (warnings.length > 0) {
            showStatus('advanced', warnings.join(' '), 'warning');
        }

        const optionsJson = { ...(json || {}) };
        delete optionsJson.warnings;

        const originalExtensions = optionsJson?.publicKey?.extensions;
        createOptions = parseCreationOptionsFromJSON(optionsJson);

        applyAuthenticatorAttachmentPreference(
            createOptions,
            allowedAttachments,
            json?.publicKey,
            publicKey,
        );

        convertedExtensions = convertExtensionsForClient(originalExtensions);
        if (convertedExtensions) {
            createOptions.publicKey = createOptions.publicKey || {};
            createOptions.publicKey.extensions = {
                ...(createOptions.publicKey.extensions || {}),
                ...convertedExtensions
            };
        }

        state.lastFakeCredLength = parseInt(document.getElementById('fake-cred-length-reg').value) || 0;
        window.lastFakeCredLength = state.lastFakeCredLength;

        showProgress('advanced', 'Connecting your authenticator device...');

        const credential = await create(createOptions);

        const authenticatorAttachment = credential && typeof credential === 'object'
            ? credential.authenticatorAttachment ?? null
            : null;
        const credentialJson = credential.toJSON ? credential.toJSON() : JSON.parse(JSON.stringify(credential));
        if (authenticatorAttachment !== undefined) {
            credentialJson.authenticatorAttachment = authenticatorAttachment;
        }
        const extensionResults = credential.getClientExtensionResults
            ? credential.getClientExtensionResults()
            : (credential.clientExtensionResults || {});
        const normalizedExtensionResults = normalizeClientExtensionResults(extensionResults);
        const existingExtensionResults = credentialJson.clientExtensionResults || {};
        if (normalizedExtensionResults && typeof normalizedExtensionResults === 'object' &&
            Object.keys(normalizedExtensionResults).length > 0) {
            credentialJson.clientExtensionResults = {
                ...existingExtensionResults,
                ...normalizedExtensionResults,
            };
        } else if (credentialJson.clientExtensionResults === undefined) {
            credentialJson.clientExtensionResults = existingExtensionResults;
        }

        showProgress('advanced', 'Completing registration...');

        const result = await fetch('/api/advanced/register/complete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ...parsed,
                __credential_response: credentialJson
            }),
        });

        if (result.ok) {
            const data = await result.json();

            printRegistrationDebug(credential, createOptions, data);

            showStatus('advanced', `Advanced registration successful! Algorithm: ${data.algo || 'Unknown'}`, 'success');

            maybeRandomizeAdvancedRegistrationFields();

            await showRegistrationResultModal(credentialJson, data.relyingParty || null);

            setTimeout(loadSavedCredentials, 1000);
        } else {
            const errorText = await result.text();
            throw new Error(`Registration failed: ${errorText}`);
        }
    } catch (error) {
        const errorName = error && typeof error === 'object' ? error.name : undefined;
        let errorMessage = error && typeof error === 'object' && typeof error.message === 'string'
            ? error.message
            : String(error);
        if (errorName === 'NotAllowedError') {
            errorMessage = 'User cancelled or authenticator not available';
        } else if (errorName === 'InvalidStateError') {
            errorMessage = 'Authenticator is already registered for this account';
        } else if (errorName === 'SecurityError') {
            errorMessage = 'Security error - check your connection and try again';
        }

        const potentialIssues = collectPotentialUnsupportedFeatures(publicKey, convertedExtensions, createOptions);
        const detailMessage = potentialIssues.length
            ? ` The authenticator may not support: ${potentialIssues.join(', ')}.`
            : '';

        showStatus('advanced', `Credential registration failed: ${errorMessage}${detailMessage}`, 'error');
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
            const message = hintError?.message || 'Invalid hint configuration.';
            showStatus('advanced', message, 'error');
            return;
        }

        hideStatus('advanced');
        showProgress('advanced', 'Detecting credentials...');

        const response = await fetch('/api/advanced/authenticate/begin', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(parsed)
        });

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error('No credentials detected. Please register a credential first.');
            }
            const errorText = await response.text();
            throw new Error(`Server error: ${errorText}`);
        }

        const json = await response.json();
        const originalExtensions = json?.publicKey?.extensions;
        const assertOptions = parseRequestOptionsFromJSON(json);

        const convertedExtensions = convertExtensionsForClient(originalExtensions);
        if (convertedExtensions) {
            assertOptions.publicKey = assertOptions.publicKey || {};
            assertOptions.publicKey.extensions = {
                ...(assertOptions.publicKey.extensions || {}),
                ...convertedExtensions
            };
        }

        state.lastFakeCredLength = parseInt(document.getElementById('fake-cred-length-auth').value) || 0;
        window.lastFakeCredLength = state.lastFakeCredLength;

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

        const result = await fetch('/api/advanced/authenticate/complete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ...parsed,
                __assertion_response: assertionJson
            }),
        });

        if (result.ok) {
            const data = await result.json();

            printAuthenticationDebug(assertion, assertOptions, data);

            showStatus('advanced', 'Advanced authentication successful!', 'success');

            maybeRandomizeAdvancedAuthenticationFields();
        } else {
            const errorText = await result.text();
            throw new Error(`Authentication failed: ${errorText}`);
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
    }
}

function enforceHintsForAdvanced(publicKey) {
    try {
        const resolved = enforceAuthenticatorAttachmentWithHints(publicKey);
        return Array.isArray(resolved) ? resolved : [];
    } catch (error) {
        showStatus('advanced', error?.message || 'Invalid hint configuration.', 'error');
        throw error;
    }
}
