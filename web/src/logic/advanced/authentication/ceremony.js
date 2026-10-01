// The Advanced tab's authentication, with no DOM: the request the editor holds,
// checked; what is asked of the server and of the authenticator, in what order;
// what each step and each outcome says; what the result panel shows. What the
// form decides is given: the hints' check, the records sent to the server, and
// the two values it reads from the form as the ceremony runs.

import { getAssertion, parseRequestOptions, requireNativeJson } from '../../shared/webauthn/native-json.js';
import { FailedResponseError, readFailedResponse } from '../../shared/api/failed-response.js';
import { ADVANCED_CEREMONY_TEXT } from '../registration/ceremony.js';

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
    const message = Object.hasOwn(AUTHENTICATION_ERROR_TEXT, error.name)
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
 * prepareForServer() (the records the server is sent), and hashAlgorithm() (the
 * Hash Algorithm, read when the ceremony gets there). It says what it does
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
    onStart = () => {},
    onProgress = () => {},
}) {
    try {
        requireNativeJson();
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
        // The browser reads the options, every extension it implements included.
        const publicKey = parseRequestOptions(json?.publicKey);

        onProgress(ADVANCED_CEREMONY_TEXT.connecting);

        // Its JSON as the browser writes it: the attachment, and every extension output in base64url.
        const { json: assertionResponse } = await getAssertion(publicKey);

        onProgress(ADVANCED_ASSERTION_TEXT.completing);

        const result = await postJson('/api/advanced/authenticate/complete', {
            ...parsed,
            __assertion_response: assertionResponse,
            __storedCredentials: storedCredentials,
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
