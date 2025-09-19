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
    applyAuthenticatorAttachmentPreference
} from './hints.js';
import {
    showStatus,
    hideStatus,
    showProgress,
    hideProgress
} from './status.js';
import { updateJsonEditor, getAdvancedCreateOptions, getAdvancedAssertOptions } from './json-editor.js';
import { showRegistrationResultModal, loadSavedCredentials } from './credential-display.js';
import { printRegistrationDebug, printAuthenticationDebug } from './auth-debug.js';
import { state } from './state.js';

export async function advancedRegister() {
    try {
        const jsonText = document.getElementById('json-editor').value;
        const parsed = JSON.parse(jsonText);

        if (!parsed.publicKey) {
            throw new Error('Invalid JSON structure: Missing "publicKey" property');
        }

        const publicKey = parsed.publicKey;

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

        const allowedAttachments = enforceHintsForAdvanced(publicKey);

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
        const originalExtensions = json?.publicKey?.extensions;
        const createOptions = parseCreationOptionsFromJSON(json);

        applyAuthenticatorAttachmentPreference(
            createOptions,
            allowedAttachments,
            json?.publicKey,
            publicKey,
        );

        const convertedExtensions = convertExtensionsForClient(originalExtensions);
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

            showRegistrationResultModal(credentialJson, data.relyingParty || null);

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
        }

        showStatus('advanced', `Credential registration failed: ${errorMessage}`, 'error');
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

        let allowedAttachments;
        try {
            allowedAttachments = ensureAuthenticationHintsAllowed(publicKey, { requireSelection: true });
        } catch (hintError) {
            const message = hintError?.message || 'Please select at least one authenticator hint before continuing.';
            showStatus('advanced', message, 'error');
            return;
        }

        if (Array.isArray(allowedAttachments) && allowedAttachments.length > 0) {
            publicKey.allowedAuthenticatorAttachments = allowedAttachments.slice();
        } else if (Object.prototype.hasOwnProperty.call(publicKey, 'allowedAuthenticatorAttachments')) {
            delete publicKey.allowedAuthenticatorAttachments;
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
        return enforceAuthenticatorAttachmentWithHints(publicKey, { requireSelection: true });
    } catch (error) {
        showStatus('advanced', error?.message || 'Please select at least one authenticator hint before continuing.', 'error');
        throw error;
    }
}
