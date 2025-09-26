import {
    create,
    get,
    parseCreationOptionsFromJSON,
    parseRequestOptionsFromJSON
} from './webauthn-json.browser-ponyfill.js';
import { convertExtensionsForClient } from './binary-utils.js';
import { showStatus, hideStatus, showProgress, hideProgress } from './status.js';
import { loadSavedCredentials } from './credential-display.js';
import { printRegistrationDebug, printAuthenticationDebug } from './auth-debug.js';
import { state } from './state.js';

export async function simpleRegister() {
    const email = document.getElementById('simple-email').value;
    if (!email) {
        showStatus('simple', 'Please enter a username.', 'error');
        return;
    }

    try {
        hideStatus('simple');
        showProgress('simple', 'Starting registration...');

        const response = await fetch(`/api/register/begin?email=${encodeURIComponent(email)}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server error: ${errorText}`);
        }

        const json = await response.json();
        const originalExtensions = json?.publicKey?.extensions;
        const createOptions = parseCreationOptionsFromJSON(json);

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

        showProgress('simple', 'Completing registration...');

        const result = await fetch(`/api/register/complete?email=${encodeURIComponent(email)}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(credential)
        });

        if (result.ok) {
            const data = await result.json();

            printRegistrationDebug(credential, createOptions, data);

            showStatus('simple', `Registration successful! Algorithm: ${data.algo || 'Unknown'}`, 'success');

            setTimeout(loadSavedCredentials, 1000);
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

        const response = await fetch(`/api/authenticate/begin?email=${encodeURIComponent(email)}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error('No credentials found for this username. Please register first.');
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
