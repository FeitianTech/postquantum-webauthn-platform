import {
    create,
    get,
    parseCreationOptionsFromJSON,
    parseRequestOptionsFromJSON
} from './webauthn-json.browser-ponyfill.js';
import { convertExtensionsForClient } from './binary-utils.js';
import { showStatus, hideStatus, showProgress, hideProgress } from './status.js';
import { loadSavedCredentials } from './credential-display.js';
import {
    printRegistrationDebug,
    printRegistrationRequestDebug,
    printAuthenticationDebug,
    logDebugGroup,
    convertForLogging,
} from './auth-debug.js';
import { state } from './state.js';
import { randomizeSimpleUsername } from './username.js';

function maybeRandomizeSimpleUsername() {
    const input = document.getElementById('simple-email');
    if (input && input.value.trim()) {
        randomizeSimpleUsername();
    }
}

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

export async function simpleRegister() {
    const email = document.getElementById('simple-email').value;
    if (!email) {
        showStatus('simple', 'Please enter a username.', 'error');
        return;
    }

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
        if (typeof window !== 'undefined') {
            window.__webauthnDebug = window.__webauthnDebug || {};
            debugFlow = {
                flow: 'simple',
                stage: 'starting',
                startedAt: new Date().toISOString(),
                email,
            };
            window.__webauthnDebug.registrationFlow = debugFlow;
        }

        hideStatus('simple');
        showProgress('simple', 'Starting registration...');

        const beginUrl = `/api/register/begin?email=${encodeURIComponent(email)}`;
        logDebugGroup('Simple registration: /api/register/begin request', () => {
            console.log('Request URL:', beginUrl);
        }, { collapsed: true });

        lastStage = 'begin-request';
        const response = await fetch(beginUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });

        lastStage = 'begin-response';
        const beginHeaders = Array.from(response.headers.entries());
        const beginText = await response.text();
        let json;
        try {
            json = beginText ? JSON.parse(beginText) : {};
        } catch (parseError) {
            console.error('Unable to parse /api/register/begin response JSON:', parseError, beginText);
            throw new Error('Server returned invalid JSON during registration begin.');
        }

        logDebugGroup('Simple registration: /api/register/begin response', () => {
            console.log('Status:', response.status, response.statusText);
            console.log('Headers:', beginHeaders);
            console.log('Body (text):', beginText);
            console.log('Body (parsed JSON):', json);
        }, { collapsed: true });

        if (!response.ok) {
            const message = json?.error || beginText || response.statusText || 'Server error';
            throw new Error(`Server error: ${message}`);
        }

        if (debugFlow) {
            debugFlow.stage = 'begin-response';
            debugFlow.beginResponse = convertForLogging(json);
        }

        const originalExtensions = json?.publicKey?.extensions;
        createOptions = parseCreationOptionsFromJSON(json);

        const convertedExtensions = convertExtensionsForClient(originalExtensions);
        if (convertedExtensions) {
            createOptions.publicKey = createOptions.publicKey || {};
            createOptions.publicKey.extensions = {
                ...(createOptions.publicKey.extensions || {}),
                ...convertedExtensions
            };
        }

        logDebugGroup('Simple registration: processed create() options', () => {
            console.log('Create options (raw object):', createOptions);
            console.log('Create options (sanitized):', convertForLogging(createOptions));
        }, { collapsed: true });

        state.lastFakeCredLength = 0;
        window.lastFakeCredLength = 0;

        showProgress('simple', 'Connecting your authenticator device...');

        requestDebugDetails = printRegistrationRequestDebug(createOptions);
        const optionsSnapshot = requestDebugDetails?.rawCreateOptionsForLogging
            || convertForLogging(createOptions);
        if (debugFlow) {
            debugFlow.stage = 'awaiting-authenticator';
            debugFlow.createOptions = optionsSnapshot;
            debugFlow.requestDetails = requestDebugDetails;
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
        logDebugGroup('Simple registration: navigator.credentials.create resolved', () => {
            console.log('Credential result:', credential);
        }, { collapsed: true });

        const credentialSnapshot = snapshotCredentialForLogging(credential);
        if (debugFlow) {
            debugFlow.stage = 'credential-created';
            debugFlow.credential = credentialSnapshot;
        }

        showProgress('simple', 'Completing registration...');

        const completeUrl = `/api/register/complete?email=${encodeURIComponent(email)}`;
        logDebugGroup('Simple registration: /api/register/complete request', () => {
            console.log('Request URL:', completeUrl);
            console.log('Request payload (credential toJSON):', credential?.toJSON ? credential.toJSON() : credential);
        }, { collapsed: true });

        if (debugFlow) {
            debugFlow.stage = 'complete-request';
        }

        lastStage = 'complete-request';
        const result = await fetch(completeUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(credential)
        });

        lastStage = 'complete-response';
        const completionHeaders = Array.from(result.headers.entries());
        const completionText = await result.text();
        let data;
        try {
            data = completionText ? JSON.parse(completionText) : {};
        } catch (parseError) {
            console.error('Unable to parse /api/register/complete response JSON:', parseError, completionText);
            throw new Error('Server returned invalid JSON during registration completion.');
        }

        logDebugGroup('Simple registration: /api/register/complete response', () => {
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

        showStatus('simple', `Registration successful! Algorithm: ${data.algo || 'Unknown'}`, 'success');

        maybeRandomizeSimpleUsername();

        setTimeout(loadSavedCredentials, 1000);

    } catch (error) {
        stopCreateTimer();

        let errorMessage = error && typeof error === 'object' && typeof error.message === 'string'
            ? error.message
            : String(error);
        const errorName = error && typeof error === 'object' ? error.name : undefined;
        if (errorName === 'NotAllowedError') {
            errorMessage = 'User cancelled or authenticator not available';
        } else if (errorName === 'InvalidStateError') {
            errorMessage = 'Authenticator is already registered for this account';
        } else if (errorName === 'SecurityError') {
            errorMessage = 'Security error - check your connection and try again';
        } else if (errorName === 'NotSupportedError') {
            errorMessage = 'WebAuthn is not supported in this browser';
        }

        logDebugGroup('Simple registration: error context', () => {
            console.error('Registration failed at stage:', lastStage);
            console.error('Error object:', error);
            if (createOptions) {
                console.log('Create options (sanitized):', convertForLogging(createOptions));
            }
            console.log('Last request debug details:', requestDebugDetails);
        }, { collapsed: false, force: true });

        if (debugFlow) {
            debugFlow.stage = 'error';
            debugFlow.error = {
                message: errorMessage,
                name: errorName || null,
                stage: lastStage,
            };
        }

        showStatus('simple', errorMessage, 'error');
    } finally {
        stopCreateTimer();
        hideProgress('simple');
    }
}

export async function simpleAuthenticate() {
    const email = document.getElementById('simple-email').value;
    if (!email) {
        showStatus('simple', 'Please enter a username. ', 'error');
        return;
    }

    try {
        hideStatus('simple');
        showProgress('simple', 'Starting authentication...');

        const response = await fetch(`/api/authenticate/begin?email=${encodeURIComponent(email)}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error('No credentials found for this email. Please register first.');
            }
            const errorText = await response.text();
            throw new Error(`Server error: ${errorText}`);
        }

        const json = await response.json();
        const getOptions = parseRequestOptionsFromJSON(json);

        state.lastFakeCredLength = 0;
        window.lastFakeCredLength = 0;

        showProgress('simple', 'Connecting your authenticator device...');

        const assertion = await get(getOptions);

        showProgress('simple', 'Completing authentication...');

        const result = await fetch(`/api/authenticate/complete?email=${encodeURIComponent(email)}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(assertion)
        });

        if (result.ok) {
            const data = await result.json();

            printAuthenticationDebug(assertion, getOptions, data);

            showStatus('simple', 'Authentication successful! You have been verified.', 'success');

            maybeRandomizeSimpleUsername();
        } else {
            const errorText = await result.text();
            throw new Error(`Authentication failed: ${errorText}`);
        }

    } catch (error) {
        let errorMessage = error.message;
        if (error.name === 'NotAllowedError') {
            errorMessage = 'User cancelled or authenticator not available';
        } else if (error.name === 'InvalidStateError') {
            errorMessage = 'Authenticator error or invalid credential';
        } else if (error.name === 'SecurityError') {
            errorMessage = 'Security error - check your connection and try again';
        } else if (error.name === 'NotSupportedError') {
            errorMessage = 'WebAuthn is not supported in this browser';
        }

        showStatus('simple', errorMessage, 'error');
    } finally {
        hideProgress('simple');
    }
}
