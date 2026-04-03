import {
    create,
    get,
    parseCreationOptionsFromJSON,
    parseRequestOptionsFromJSON
} from '../shared/webauthn-json.browser-ponyfill.js';
import { convertExtensionsForClient } from '../shared/binary-utils.js';
import { showStatus, hideStatus, showProgress, hideProgress } from '../shared/status.js';
import {
    loadSavedCredentials,
    queueAuthenticatedCredentialFlash,
    queueFailedCredentialFlash,
    updateCredentialsDisplay,
} from '../advanced/credential-display.js';
import { printRegistrationDebug, printAuthenticationDebug } from '../shared/auth-debug.js';
import { state } from '../shared/state.js';
import {
    getSimpleCredentialsForEmail,
    saveSimpleCredential,
    prepareCredentialsForServer,
    updateSimpleCredentialSignCount,
} from '../shared/local-storage.js';

let simpleRegisterState = null;
let simpleAuthenticateState = null;

export async function simpleRegister() {
    const email = document.getElementById('simple-email').value;
    if (!email) {
        showStatus('simple', 'Please enter a username.', 'error');
        return;
    }

    try {
        hideStatus('simple');
        showProgress('simple', 'Starting registration...');

        const registrationPayload = {};

        const response = await fetch(`/api/register/begin?email=${encodeURIComponent(email)}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(registrationPayload)
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server error: ${errorText}`);
        }

        const json = await response.json();
        const { __session_state: sessionState = null, ...optionsWithoutState } = json || {};
        simpleRegisterState = sessionState;
        const originalExtensions = optionsWithoutState?.publicKey?.extensions;
        const createOptions = parseCreationOptionsFromJSON(optionsWithoutState);

        const convertedExtensions = convertExtensionsForClient(originalExtensions);
        if (convertedExtensions) {
            createOptions.publicKey = createOptions.publicKey || {};
            createOptions.publicKey.extensions = {
                ...(createOptions.publicKey.extensions || {}),
                ...convertedExtensions
            };
        }

        state.lastFakeCredLength = 0;
        window.lastFakeCredLength = 0;

        showProgress('simple', 'Connecting your authenticator device...');

        const credential = await create(createOptions);
        const credentialJson = credential.toJSON ? credential.toJSON() : JSON.parse(JSON.stringify(credential));
        if (simpleRegisterState) {
            credentialJson.__session_state = simpleRegisterState;
        }

        showProgress('simple', 'Completing registration...');

        const result = await fetch(`/api/register/complete?email=${encodeURIComponent(email)}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(credentialJson)
        });

        if (result.ok) {
            const data = await result.json();

            printRegistrationDebug(credential, createOptions, data);

            showStatus('simple', `Registration successful! Algorithm: ${data.algo || 'Unknown'}`, 'success');

            if (data.storedCredential && typeof data.storedCredential === 'object') {
                saveSimpleCredential({ ...data.storedCredential, email });
                loadSavedCredentials();
            }

            setTimeout(loadSavedCredentials, 1000);
            simpleRegisterState = null;
        } else {
            const errorText = await result.text();
            throw new Error(`Registration failed: ${errorText}`);
        }

    } catch (error) {
        let errorMessage = error.message;
        if (error.name === 'NotAllowedError') {
            errorMessage = 'User cancelled or authenticator not available';
        } else if (error.name === 'InvalidStateError') {
            errorMessage = 'Authenticator is already registered for this account';
        } else if (error.name === 'SecurityError') {
            errorMessage = 'Security error - check your connection and try again';
        } else if (error.name === 'NotSupportedError') {
            errorMessage = 'WebAuthn is not supported in this browser';
        }

        showStatus('simple', errorMessage, 'error');
    } finally {
        hideProgress('simple');
        simpleRegisterState = null;
    }
}

export async function simpleAuthenticate() {
    const email = document.getElementById('simple-email').value;
    if (!email) {
        showStatus('simple', 'Please enter a username.', 'error');
        return;
    }

    try {
        hideStatus('simple');
        showProgress('simple', 'Starting authentication...');

        const storedCredentials = getSimpleCredentialsForEmail(email);
        if (!storedCredentials.length) {
            throw new Error('No credentials stored in this browser for the provided username. Please register first.');
        }

        const authenticatePayload = {
            credentials: prepareCredentialsForServer(storedCredentials)
        };

        const response = await fetch(`/api/authenticate/begin?email=${encodeURIComponent(email)}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(authenticatePayload)
        });

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error('No credentials found for this username. Please register first.');
            }
            const errorText = await response.text();
            throw new Error(`Server error: ${errorText}`);
        }

        const json = await response.json();
        const { __session_state: sessionState = null, ...optionsWithoutState } = json || {};
        simpleAuthenticateState = sessionState;
        const getOptions = parseRequestOptionsFromJSON(optionsWithoutState);

        state.lastFakeCredLength = 0;
        window.lastFakeCredLength = 0;

        showProgress('simple', 'Connecting your authenticator device...');

        const assertion = await get(getOptions);
        const assertionJson = assertion.toJSON ? assertion.toJSON() : JSON.parse(JSON.stringify(assertion));
        if (simpleAuthenticateState) {
            assertionJson.__session_state = simpleAuthenticateState;
        }

        showProgress('simple', 'Completing authentication...');

        const result = await fetch(`/api/authenticate/complete?email=${encodeURIComponent(email)}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(assertionJson)
        });

        if (result.ok) {
            const data = await result.json();

            printAuthenticationDebug(assertion, getOptions, data);

            showStatus('simple', 'Authentication successful! You have been verified.', 'success');

            if (data.authenticatedCredentialId) {
                updateSimpleCredentialSignCount(
                    email,
                    data.authenticatedCredentialId,
                    typeof data.signCount === 'number' ? data.signCount : undefined
                );
                queueAuthenticatedCredentialFlash(data.authenticatedCredentialId);
                loadSavedCredentials();
            }
            simpleAuthenticateState = null;
        } else {
            const errorText = await result.text();
            let parsedError = null;
            try {
                parsedError = JSON.parse(errorText);
            } catch (parseError) {
                parsedError = null;
            }

            if (parsedError && typeof parsedError.failedCredentialId === 'string') {
                queueFailedCredentialFlash(parsedError.failedCredentialId);
                updateCredentialsDisplay();
            }

            const message = parsedError && typeof parsedError.error === 'string'
                ? parsedError.error
                : (errorText || `Authentication failed (${result.status})`);
            throw new Error(message);
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
        simpleAuthenticateState = null;
    }
}
