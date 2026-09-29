// The Simple tab's two ceremonies, with no DOM: what is asked of the server and
// of the authenticator, in what order, and what each step and each outcome says.
// The saved credentials are kept through the storage it imports; the tab says
// what happened its own way.

import {
    create,
    get,
    parseCreationOptionsFromJSON,
    parseRequestOptionsFromJSON,
} from '../shared/webauthn/json-ponyfill.js';
import { FailedResponseError, readFailedResponse } from '../shared/api/failed-response.js';
import { convertExtensionsForClient } from '../shared/utils/binary.js';
import { printAuthenticationDebug, printRegistrationDebug } from '../shared/debug/auth.js';
import { state } from '../shared/state.js';

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

/** The success toast of a registration, naming the algorithm the server chose. */
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
 */
export function ceremonyErrorText(error, ceremony) {
    const name = error?.name;
    if (name === 'InvalidStateError') {
        return INVALID_STATE_TEXT[ceremony];
    }
    if (Object.prototype.hasOwnProperty.call(ERROR_NAME_TEXT, name)) {
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

// The options without the server's session state, which goes back with the answer.
function splitSessionState(json) {
    const { __session_state: sessionState = null, ...options } = json || {};
    return [sessionState, options];
}

// The ponyfill's create() and get() give every credential its toJSON().
function credentialToJson(credential, sessionState) {
    const json = credential.toJSON();
    if (sessionState) {
        json.__session_state = sessionState;
    }
    return json;
}

/**
 * Registers a passkey for `email`: the server's options, the authenticator's
 * credential, the server's verdict. Says each step through onProgress. Gives the
 * server's answer (its storedCredential is what the browser keeps); throws a
 * FailedResponseError for a refused request, or the browser's error.
 */
export async function registerSimplePasskey(email, { onProgress = () => {} } = {}) {
    onProgress(SIMPLE_CEREMONY_TEXT.registrationStarting);
    const response = await postJson('/api/register/begin', email, {});
    if (!response.ok) {
        throw new FailedResponseError(await readFailedResponse(response), 'Registration could not start');
    }

    const [sessionState, options] = splitSessionState(await response.json());
    const originalExtensions = options?.publicKey?.extensions;
    const createOptions = parseCreationOptionsFromJSON(options);
    const convertedExtensions = convertExtensionsForClient(originalExtensions);
    if (convertedExtensions) {
        // The parsed options always hold publicKey (the ponyfill requires it).
        createOptions.publicKey.extensions = {
            ...createOptions.publicKey.extensions,
            ...convertedExtensions,
        };
    }
    state.lastFakeCredLength = 0;

    onProgress(SIMPLE_CEREMONY_TEXT.connecting);
    const credential = await create(createOptions);
    const credentialJson = credentialToJson(credential, sessionState);

    onProgress(SIMPLE_CEREMONY_TEXT.registrationCompleting);
    const result = await postJson('/api/register/complete', email, credentialJson);
    if (!result.ok) {
        throw new FailedResponseError(await readFailedResponse(result), 'Registration failed');
    }
    const answer = await result.json();
    printRegistrationDebug(credential, createOptions, answer);
    return answer;
}

/**
 * Authenticates `email` with the passkeys this browser keeps for it:
 * `credentialsFor(email)` gives them, `prepareForServer(records)` what the server
 * is sent of them. Says each step through onProgress. Gives
 * `{answer, result}` on success, `{failure, result}` when the server refused the
 * assertion (readFailedResponse's reading; `result` is what the result panel
 * shows: shared/ceremony/result.js); throws for anything before that.
 */
export async function authenticateSimplePasskey(email, { credentialsFor, prepareForServer, onProgress = () => {} }) {
    onProgress(SIMPLE_CEREMONY_TEXT.authenticationStarting);
    const storedCredentials = credentialsFor(email);
    if (!storedCredentials.length) {
        throw new Error(SIMPLE_CEREMONY_TEXT.noStoredCredentials);
    }

    const response = await postJson('/api/authenticate/begin', email, {
        credentials: prepareForServer(storedCredentials),
    });
    if (!response.ok) {
        if (response.status === 404) {
            throw new Error(SIMPLE_CEREMONY_TEXT.noServerCredentials);
        }
        throw new FailedResponseError(await readFailedResponse(response), 'Authentication could not start');
    }

    const [sessionState, options] = splitSessionState(await response.json());
    const getOptions = parseRequestOptionsFromJSON(options);
    state.lastFakeCredLength = 0;

    onProgress(SIMPLE_CEREMONY_TEXT.connecting);
    const assertion = await get(getOptions);
    const assertionJson = credentialToJson(assertion, sessionState);

    onProgress(SIMPLE_CEREMONY_TEXT.authenticationCompleting);
    const result = await postJson('/api/authenticate/complete', email, assertionJson);
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
    printAuthenticationDebug(assertion, getOptions, answer);
    return {
        answer,
        result: {
            title: SIMPLE_CEREMONY_TEXT.lastAuthentication,
            signCount: answer.signCount,
            signCountStatus: answer.signCountStatus,
        },
    };
}
