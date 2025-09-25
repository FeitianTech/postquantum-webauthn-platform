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
import {
    printRegistrationDebug,
    printRegistrationRequestDebug,
    printAuthenticationDebug,
    logDebugGroup,
    convertForLogging,
} from './auth-debug.js';
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

function snapshotCredentialForLogging(credential) {
    if (!credential || typeof credential !== 'object') {
        return null;
    }

    const base = {
        id: credential.id || null,
        type: credential.type || null,
        rawId: credential.rawId || null,
        authenticatorAttachment: credential.authenticatorAttachment ?? null,
    };

    const response = credential.response;
    if (response && typeof response === 'object') {
        base.response = {
            attestationObject: response.attestationObject,
            clientDataJSON: response.clientDataJSON,
            transports: typeof response.getTransports === 'function'
                ? (() => {
                    try {
                        return response.getTransports();
                    } catch (error) {
                        console.warn('Unable to read transports from credential response:', error);
                        return undefined;
                    }
                })()
                : undefined,
        };
    }

    const extensions = credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : credential.clientExtensionResults;
    if (extensions) {
        base.clientExtensionResults = extensions;
    }

    try {
        return convertForLogging(base);
    } catch (error) {
        console.warn('Unable to normalise credential snapshot for logging:', error);
        return base;
    }
}

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
    let requestDebugDetails = null;
    let debugFlow = null;
    let lastStage = 'initial';
    let createTimerLabel = '';
    let createTimerActive = false;

    const stopCreateTimer = () => {
        if (createTimerActive && typeof console.timeEnd === 'function' && createTimerLabel) {
            try {
                console.timeEnd(createTimerLabel);
            } catch (timerError) {
                console.warn('Unable to stop navigator.credentials.create() timer:', timerError);
            }
            createTimerActive = false;
        }
    };

    try {
        const jsonText = document.getElementById('json-editor').value;
        const parsed = JSON.parse(jsonText);

        if (typeof window !== 'undefined') {
            window.__webauthnDebug = window.__webauthnDebug || {};
            debugFlow = {
                flow: 'advanced',
                stage: 'parsed-json',
                startedAt: new Date().toISOString(),
            };
            window.__webauthnDebug.registrationFlow = debugFlow;
        }

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

        if (debugFlow) {
            debugFlow.stage = 'begin-request';
            debugFlow.beginRequest = convertForLogging(parsed);
        }

        logDebugGroup('Advanced registration: /api/advanced/register/begin request', () => {
            console.log('Request body:', parsed);
        }, { collapsed: true });

        lastStage = 'begin-request';
        const response = await fetch('/api/advanced/register/begin', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(parsed)
        });

        lastStage = 'begin-response';
        const beginHeaders = Array.from(response.headers.entries());
        const beginText = await response.text();
        let json;
        try {
            json = beginText ? JSON.parse(beginText) : {};
        } catch (parseError) {
            console.error('Unable to parse /api/advanced/register/begin response JSON:', parseError, beginText);
            throw new Error('Server returned invalid JSON during registration begin.');
        }

        logDebugGroup('Advanced registration: /api/advanced/register/begin response', () => {
            console.log('Status:', response.status, response.statusText);
            console.log('Headers:', beginHeaders);
            console.log('Body (text):', beginText);
            console.log('Body (parsed JSON):', json);
        }, { collapsed: true });

        if (!response.ok) {
            const message = json?.error || beginText || response.statusText || 'Server error';
            throw new Error(`Server error: ${message}`);
        }

        const { warnings: beginWarnings, ...creationPayload } = json || {};

        if (debugFlow) {
            debugFlow.stage = 'begin-response';
            debugFlow.beginResponse = convertForLogging(json);
            if (beginWarnings) {
                debugFlow.beginWarnings = convertForLogging(beginWarnings);
            }
        }

        if (beginWarnings?.pqc?.message) {
            showStatus('advanced', beginWarnings.pqc.message, 'warning');
        }

        const originalExtensions = creationPayload?.publicKey?.extensions;
        createOptions = parseCreationOptionsFromJSON(creationPayload);

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

        logDebugGroup('Advanced registration: processed create() options', () => {
            console.log('Allowed attachments:', allowedAttachments);
            console.log('Create options (raw object):', createOptions);
            console.log('Create options (sanitized):', convertForLogging(createOptions));
        }, { collapsed: true });

        state.lastFakeCredLength = parseInt(document.getElementById('fake-cred-length-reg').value) || 0;
        window.lastFakeCredLength = state.lastFakeCredLength;

        showProgress('advanced', 'Connecting your authenticator device...');

        requestDebugDetails = printRegistrationRequestDebug(createOptions);

        const optionsSnapshot = requestDebugDetails?.rawCreateOptionsForLogging
            || convertForLogging(createOptions);
        if (debugFlow) {
            debugFlow.stage = 'awaiting-authenticator';
            debugFlow.requestDetails = requestDebugDetails;
            debugFlow.createOptions = optionsSnapshot;
        }

        createTimerLabel = `navigator.credentials.create() ${new Date().toISOString()}`;
        if (typeof console.time === 'function') {
            console.time(createTimerLabel);
            createTimerActive = true;
        }

        lastStage = 'awaiting-credential';
        const credential = await create(createOptions);
        stopCreateTimer();

        lastStage = 'credential-created';
        logDebugGroup('Advanced registration: navigator.credentials.create resolved', () => {
            console.log('Credential result:', credential);
        }, { collapsed: true });

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

        const credentialSnapshot = snapshotCredentialForLogging(credential);
        if (debugFlow) {
            debugFlow.stage = 'credential-created';
            debugFlow.credential = credentialSnapshot;
            debugFlow.credentialJson = credentialJson;
        }

        showProgress('advanced', 'Completing registration...');

        const completionPayload = {
            ...parsed,
            __credential_response: credentialJson,
        };

        logDebugGroup('Advanced registration: /api/advanced/register/complete request', () => {
            console.log('Request body:', completionPayload);
        }, { collapsed: true });

        if (debugFlow) {
            debugFlow.stage = 'complete-request';
            debugFlow.completionRequest = convertForLogging(completionPayload);
        }

        lastStage = 'complete-request';
        const result = await fetch('/api/advanced/register/complete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(completionPayload),
        });

        lastStage = 'complete-response';
        const completionHeaders = Array.from(result.headers.entries());
        const completionText = await result.text();
        let data;
        try {
            data = completionText ? JSON.parse(completionText) : {};
        } catch (parseError) {
            console.error('Unable to parse /api/advanced/register/complete response JSON:', parseError, completionText);
            throw new Error('Server returned invalid JSON during registration completion.');
        }

        logDebugGroup('Advanced registration: /api/advanced/register/complete response', () => {
            console.log('Status:', result.status, result.statusText);
            console.log('Headers:', completionHeaders);
            console.log('Body (text):', completionText);
            console.log('Body (parsed JSON):', data);
        }, { collapsed: true });

        if (!result.ok) {
            const errorMessage = data?.error || completionText || result.statusText || 'Unknown error';
            throw new Error(`Registration failed: ${errorMessage}`);
        }

        if (debugFlow) {
            debugFlow.stage = 'complete';
            debugFlow.serverResponse = data;
        }

        printRegistrationDebug(credential, createOptions, data, requestDebugDetails);

        showStatus('advanced', `Advanced registration successful! Algorithm: ${data.algo || 'Unknown'}`, 'success');

        maybeRandomizeAdvancedRegistrationFields();

        await showRegistrationResultModal(credentialJson, data.relyingParty || null);

        setTimeout(loadSavedCredentials, 1000);
    } catch (error) {
        stopCreateTimer();

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

        logDebugGroup('Advanced registration: error context', () => {
            console.error('Registration failed at stage:', lastStage);
            console.error('Error object:', error);
            console.log('Last request debug details:', requestDebugDetails);
            if (createOptions) {
                console.log('Create options (sanitized):', convertForLogging(createOptions));
            }
        }, { collapsed: false, force: true });

        if (debugFlow) {
            debugFlow.stage = 'error';
            debugFlow.error = {
                message: errorMessage,
                name: errorName || null,
                stage: lastStage,
            };
        }
    } finally {
        stopCreateTimer();
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
