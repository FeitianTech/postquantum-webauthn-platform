// The Advanced tab's authentication, with no DOM: the request the editor holds,
// checked; what is asked of the server and of the authenticator, in what order;
// what each step and each outcome says; what the result panel shows. The
// current tab (./advanced.js) and the new UI both run it. What the form's views
// decide is given: the hints' check (./hints.js, which the current tab's tests
// replace), the records sent to the server, and the two values it reads from
// the form as the ceremony runs.

import { get, parseRequestOptionsFromJSON } from '../../shared/webauthn/json-ponyfill.js';
import { convertExtensionsForClient, normalizeClientExtensionResults } from '../../shared/utils/binary.js';
import { printAuthenticationDebug } from '../../shared/debug/auth.js';
import { FailedResponseError, readFailedResponse } from '../../shared/api/failed-response.js';
import { state } from '../../shared/state.js';
import { ADVANCED_CEREMONY_TEXT } from './ceremony.js';

export const ADVANCED_ASSERTION_TEXT = {
    missingChallenge: 'Invalid CredentialRequestOptions: Missing required "challenge" property',
    detecting: 'Detecting credentials...',
    completing: 'Completing authentication...',
    noCredentials: 'No credentials detected. Please register a credential first.',
    lastAuthentication: 'Last authentication',
    authenticated: 'Advanced authentication successful!',
    notRejected: 'The advanced tab reports this and does not reject the assertion.',
};

const AUTHENTICATION_ERROR_TEXT = {
    NotAllowedError: 'User cancelled or no compatible authenticator detected',
    InvalidStateError: 'Invalid authenticator state - please try again',
    SecurityError: 'Security error - check your connection and try again',
};

/** What a failed authentication says: the browser's refusals by name, anything else by its own message. */
export function advancedAuthenticationFailureText(error) {
    const message = Object.prototype.hasOwnProperty.call(AUTHENTICATION_ERROR_TEXT, error.name)
        ? AUTHENTICATION_ERROR_TEXT[error.name]
        : error.message;
    return `Advanced authentication failed: ${message}`;
}

/**
 * The editor's text as an authentication's request: the object it parses to,
 * holding publicKey with a challenge, or the sentence that says what is missing
 * (the parser's error for text that is not JSON).
 */
export function readAssertionRequest(text) {
    const parsed = JSON.parse(text);

    if (!parsed.publicKey) {
        throw new Error(ADVANCED_CEREMONY_TEXT.missingPublicKey);
    }
    if (!parsed.publicKey.challenge) {
        throw new Error(ADVANCED_ASSERTION_TEXT.missingChallenge);
    }
    return parsed;
}

// The assertion as the server is sent it: its JSON (the ponyfill's get() gives
// every assertion its toJSON()), with its attachment and every client
// extension result, read from the assertion when it can give them.
function assertionJson(assertion) {
    const json = assertion.toJSON();
    json.authenticatorAttachment = assertion.authenticatorAttachment ?? null;
    const extensionResults = assertion.getClientExtensionResults
        ? assertion.getClientExtensionResults()
        : (assertion.clientExtensionResults || {});
    const normalizedExtensionResults = normalizeClientExtensionResults(extensionResults);
    const existingExtensionResults = json.clientExtensionResults || {};
    if (normalizedExtensionResults && typeof normalizedExtensionResults === 'object' &&
        Object.keys(normalizedExtensionResults).length > 0) {
        json.clientExtensionResults = {
            ...existingExtensionResults,
            ...normalizedExtensionResults,
        };
    } else if (json.clientExtensionResults === undefined) {
        json.clientExtensionResults = existingExtensionResults;
    }
    return json;
}

function postJson(path, body) {
    return fetch(path, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body),
    });
}

/**
 * Authenticates with the editor's text. The form's views give: ensureHints
 * (the hints' check, which may narrow allowCredentials and may throw),
 * prepareForServer() (the records the server is sent), and hashAlgorithm() and
 * fakeCredentialLength() (the Hash Algorithm, and the fake ID length for the
 * debug print), each read when the ceremony gets there. It says what it does
 * through onStart (the request checked: the last ceremony's messages may go)
 * and onProgress. Gives `{authenticated: true, answer, result}`, or
 * `{authenticated: false, text, result, failedCredentialId}` with the
 * failure's sentence (the result panel's input, shared/ceremony/result.js,
 * when the server answered the assertion; the credential it refused, if it
 * named one). A refusal of the hints says its own message alone.
 */
export async function authenticateAdvancedCredential(text, {
    ensureHints,
    prepareForServer,
    hashAlgorithm,
    fakeCredentialLength,
    onStart = () => {},
    onProgress = () => {},
}) {
    try {
        const parsed = readAssertionRequest(text);

        try {
            ensureHints(parsed.publicKey);
        } catch (hintError) {
            return { authenticated: false, text: hintError.message || ADVANCED_CEREMONY_TEXT.invalidHints };
        }

        onStart();
        onProgress(ADVANCED_ASSERTION_TEXT.detecting);

        const storedCredentials = prepareForServer();
        const response = await postJson('/api/advanced/authenticate/begin', {
            ...parsed,
            __storedCredentials: storedCredentials,
        });

        if (!response.ok) {
            const failure = await readFailedResponse(response);
            if (response.status === 404 && !failure.body?.error) {
                throw new Error(ADVANCED_ASSERTION_TEXT.noCredentials);
            }
            throw new FailedResponseError(failure);
        }

        const json = await response.json();
        const sessionState = json?.__session_state ?? null;
        const optionsJson = { ...json };
        delete optionsJson.__session_state;
        const originalExtensions = optionsJson.publicKey?.extensions;
        const assertOptions = parseRequestOptionsFromJSON(optionsJson);

        const convertedExtensions = convertExtensionsForClient(originalExtensions);
        if (convertedExtensions) {
            // Extensions to convert come with a publicKey, which the parsed options keep.
            assertOptions.publicKey.extensions = {
                ...(assertOptions.publicKey.extensions || {}),
                ...convertedExtensions
            };
        }

        state.lastFakeCredLength = fakeCredentialLength();

        onProgress(ADVANCED_CEREMONY_TEXT.connecting);

        const assertion = await get(assertOptions);
        const assertionResponse = assertionJson(assertion);

        onProgress(ADVANCED_ASSERTION_TEXT.completing);

        const result = await postJson('/api/advanced/authenticate/complete', {
            ...parsed,
            __assertion_response: assertionResponse,
            __storedCredentials: storedCredentials,
            __session_state: sessionState,
            __hash_algorithm: hashAlgorithm(),
        });

        if (!result.ok) {
            const failure = await readFailedResponse(result);
            return {
                authenticated: false,
                text: advancedAuthenticationFailureText(new FailedResponseError(failure)),
                failedCredentialId: failure.failedCredentialId,
                result: {
                    title: ADVANCED_ASSERTION_TEXT.lastAuthentication,
                    signCountStatus: failure.signCountStatus,
                    showChallenge: true,
                    challengeSource: failure.challengeSource,
                    challengeStatus: failure.challengeStatus,
                },
            };
        }

        const answer = await result.json();
        printAuthenticationDebug(assertion, assertOptions, answer);
        return {
            authenticated: true,
            answer,
            result: {
                title: ADVANCED_ASSERTION_TEXT.lastAuthentication,
                signCount: answer.signCount,
                signCountStatus: answer.signCountStatus,
                consequence: ADVANCED_ASSERTION_TEXT.notRejected,
                showChallenge: true,
                challengeSource: answer.challengeSource,
                challengeStatus: answer.challengeStatus,
            },
        };
    } catch (error) {
        return { authenticated: false, text: advancedAuthenticationFailureText(error) };
    }
}
