// The Simple tab's two ceremonies, with no DOM: what is asked of the server and
// of the authenticator, in what order, and what each step and each outcome says.
// The saved credentials are kept through the storage it imports; the tab says
// what happened its own way.

import {
    createCredential,
    getAssertion,
    parseCreationOptions,
    parseRequestOptions,
    requireNativeJson,
} from '../shared/native-json.js';
import { FailedResponseError, readFailedResponse } from '../shared/failed-response.js';
import {
    getSimpleCredentialsForEmail,
    prepareCredentialsForServer,
    saveSimpleCredential,
} from '../credentials/storage/local/simple-credentials.js';

/** @import { CeremonyResultInput } from '../shared/ceremony-result.js' */

/**
 * @typedef {'registration' | 'authentication'} Ceremony
 */

/**
 * What the server answered a registration: storedCredential is what this browser keeps.
 * @typedef {{ algo?: string, storedCredential?: Record<string, unknown> | null, [field: string]: unknown }} RegistrationAnswer
 */

/**
 * What the server answered an assertion it accepted.
 * @typedef {{ authenticatedCredentialId?: string, signCount?: number, signCountStatus?: string, [field: string]: unknown }} AuthenticationAnswer
 */

/**
 * An authentication's end: the server's answer, or the assertion it refused (as
 * readFailedResponse read it), and what the result panel shows either way.
 * @typedef {(
 *     | { answer: AuthenticationAnswer, failure?: undefined, result: CeremonyResultInput }
 *     | { answer?: undefined, failure: { text: string, failedCredentialId: string | null, signCountStatus: string | null }, result: CeremonyResultInput }
 * )} AuthenticationOutcome
 */

export const SIMPLE_CEREMONY_TEXT = {
    usernameRequired: 'Please enter a username.',
    registrationStarting: 'Starting registration...',
    connecting: 'Connecting your authenticator device...',
    registrationCompleting: 'Completing registration...',
    authenticationStarting: 'Starting authentication...',
    authenticationCompleting: 'Completing authentication...',
    authenticated: 'Authentication successful! You have been verified.',
    noStoredCredentials: 'No credentials stored in this browser for the provided username. Please register first.',
    noServerCredentials: 'No credentials found for this username. Please register first.',
    rejected: 'Authentication was rejected.',
    lastAuthentication: 'Last authentication',
};

/**
 * The success toast of a registration, naming the algorithm the server chose.
 * @param {RegistrationAnswer | null | undefined} answer
 * @returns {string}
 */
export function registeredText(answer) {
    return `Registration successful! Algorithm: ${answer?.algo || 'Unknown'}`;
}

const ERROR_NAME_TEXT = {
    NotAllowedError: 'User cancelled or authenticator not available',
    SecurityError: 'Security error - check your connection and try again',
    NotSupportedError: 'WebAuthn is not supported in this browser',
};

const INVALID_STATE_TEXT = {
    registration: 'Authenticator is already registered for this account',
    authentication: 'Authenticator error or invalid credential',
};

/**
 * What to say when a ceremony ("registration" or "authentication") fails: the
 * browser's refusals by their name (an InvalidStateError says something else in
 * each), anything else by its own message (a refused request's is
 * readFailedResponse's, prefixed by the step).
 * @param {any} error
 * @param {Ceremony} ceremony
 * @returns {string}
 */
export function ceremonyErrorText(error, ceremony) {
    const name = error?.name;
    if (name === 'InvalidStateError') {
        return INVALID_STATE_TEXT[ceremony];
    }
    if (Object.hasOwn(ERROR_NAME_TEXT, name)) {
        return ERROR_NAME_TEXT[name];
    }
    return error?.message;
}

function postJson(path, email, body) {
    return fetch(`${path}?email=${encodeURIComponent(email)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
}

/**
 * Registers a passkey for `email`: the server's options, the authenticator's
 * credential, the server's verdict. Says each step through onProgress. Gives the
 * server's answer (its storedCredential is what the browser keeps); throws a
 * FailedResponseError for a refused request, or the browser's error. A browser
 * without WebAuthn's JSON methods (shared/native-json.js) is asked
 * nothing: an UnsupportedBrowserError before the first request.
 * @param {string} email
 * @param {{ onProgress?: (text: string) => void }} [steps]
 * @returns {Promise<RegistrationAnswer>}
 */
export async function registerSimplePasskey(email, { onProgress = () => {} } = {}) {
    requireNativeJson();
    onProgress(SIMPLE_CEREMONY_TEXT.registrationStarting);
    const response = await postJson('/api/register/begin', email, {});
    if (!response.ok) {
        throw new FailedResponseError(await readFailedResponse(response), 'Registration could not start');
    }

    const options = await response.json();
    const publicKey = parseCreationOptions(options?.publicKey);

    onProgress(SIMPLE_CEREMONY_TEXT.connecting);
    const { json: credentialJson } = await createCredential(publicKey);

    onProgress(SIMPLE_CEREMONY_TEXT.registrationCompleting);
    const result = await postJson('/api/register/complete', email, credentialJson);
    if (!result.ok) {
        throw new FailedResponseError(await readFailedResponse(result), 'Registration failed');
    }
    return result.json();
}

/**
 * Authenticates `email` with the passkeys this browser keeps for it, sending the
 * server what it keeps of each, at begin and again, the very same list, with the
 * assertion (the server keeps only a digest of it). Says each step through onProgress. Gives
 * `{answer, result}` on success, `{failure, result}` when the server refused the
 * assertion (readFailedResponse's reading; `result` is what the result panel
 * shows: shared/ceremony-result.js); throws for anything before that.
 * @param {string} email
 * @param {{ onProgress?: (text: string) => void }} [steps]
 * @returns {Promise<AuthenticationOutcome>}
 */
export async function authenticateSimplePasskey(email, { onProgress = () => {} } = {}) {
    requireNativeJson();
    onProgress(SIMPLE_CEREMONY_TEXT.authenticationStarting);
    const storedCredentials = getSimpleCredentialsForEmail(email);
    if (!storedCredentials.length) {
        throw new Error(SIMPLE_CEREMONY_TEXT.noStoredCredentials);
    }

    const credentials = prepareCredentialsForServer(storedCredentials);
    const response = await postJson('/api/authenticate/begin', email, { credentials });
    if (!response.ok) {
        if (response.status === 404) {
            throw new Error(SIMPLE_CEREMONY_TEXT.noServerCredentials);
        }
        throw new FailedResponseError(await readFailedResponse(response), 'Authentication could not start');
    }

    const options = await response.json();
    const publicKey = parseRequestOptions(options?.publicKey);

    onProgress(SIMPLE_CEREMONY_TEXT.connecting);
    const { json: assertionJson } = await getAssertion(publicKey);

    onProgress(SIMPLE_CEREMONY_TEXT.authenticationCompleting);
    const result = await postJson('/api/authenticate/complete', email, { credential: assertionJson, credentials });
    if (!result.ok) {
        const failure = await readFailedResponse(result);
        return {
            failure,
            result: {
                title: SIMPLE_CEREMONY_TEXT.lastAuthentication,
                signCountStatus: failure.signCountStatus,
                consequence: SIMPLE_CEREMONY_TEXT.rejected,
            },
        };
    }
    const answer = await result.json();
    return {
        answer,
        result: {
            title: SIMPLE_CEREMONY_TEXT.lastAuthentication,
            signCount: answer.signCount,
            signCountStatus: answer.signCountStatus,
        },
    };
}

/**
 * Keeps what a registration saved in this browser: the server's record, for this email.
 * @param {Record<string, unknown>} storedCredential
 * @param {string} email
 */
export function keepSimpleCredential(storedCredential, email) {
    saveSimpleCredential({ ...storedCredential, email });
}
