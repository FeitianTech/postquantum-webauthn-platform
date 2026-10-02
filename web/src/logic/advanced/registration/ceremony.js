// The Advanced tab's registration, with no DOM: the request the editor holds,
// checked; what is asked of the server and of the authenticator, in what order;
// what each step and each outcome says; the record the browser keeps. What the
// form decides is given: the hints' rules, and the two values it reads from the
// form as the ceremony runs.

import { createCredential, parseCreationOptions, requireNativeJson } from '../../shared/native-json.js';
import { bufferSourceToUint8Array, bytesToHex } from '../../shared/bytes.js';
import { FailedResponseError, readFailedResponse } from '../../shared/failed-response.js';
/** @import { CeremonyResultInput } from '../../shared/ceremony-result.js' */

export const ADVANCED_CEREMONY_TEXT = {
    missingPublicKey: 'Invalid JSON structure: Missing "publicKey" property',
    missingRp: 'Invalid CredentialCreationOptions: Missing required "rp" property',
    missingUser: 'Invalid CredentialCreationOptions: Missing required "user" property',
    missingChallenge: 'Invalid CredentialCreationOptions: Missing required "challenge" property',
    registrationStarting: 'Starting advanced registration...',
    connecting: 'Connecting your authenticator device...',
    registrationCompleting: 'Completing registration...',
    lastRegistration: 'Last registration',
    invalidHints: 'Invalid hint configuration.',
};

const COMMON_SUPPORTED_ALGORITHMS = new Set([-7, -257, -8]);
// The DOMException names navigator.credentials.create() rejects with.
const AUTHENTICATOR_ERROR_NAMES = new Set([
    'NotAllowedError',
    'NotSupportedError',
    'InvalidStateError',
    'ConstraintError',
    'UnknownError',
    'AbortError',
]);

const REGISTRATION_ERROR_TEXT = {
    NotAllowedError: 'User cancelled or authenticator not available',
    InvalidStateError: 'Authenticator is already registered for this account',
    SecurityError: 'Security error - check your connection and try again',
};

/**
 * What of the request an authenticator may not support, in the order the failure
 * names them: from the editor's publicKey, and the options the browser was given.
 */
export function collectPotentialUnsupportedFeatures(publicKeyOptions, createOptions) {
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

    const pubKeyOptions = createOptions && typeof createOptions === 'object' && createOptions.publicKey && typeof createOptions.publicKey === 'object'
        ? createOptions.publicKey
        : null;

    const extensionSources = [publicKeyOptions.extensions, pubKeyOptions?.extensions]
        .filter(source => source && typeof source === 'object');

    const extensionLabels = [
        ['largeBlob', 'largeBlob extension'],
        ['prf', 'prf extension'],
        ['minPinLength', 'minPinLength extension'],
        ['credentialProtectionPolicy', 'credProtect extension'],
        ['credProps', 'credProps extension'],
    ];

    extensionSources.forEach(source => {
        extensionLabels.forEach(([key, label]) => {
            if (Object.hasOwn(source, key) && !issues.includes(label)) {
                issues.push(label);
            }
        });
    });

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

/**
 * What a failed registration says: the browser's refusals by name, anything else
 * by its own message; when the authenticator refused, what of the request
 * (context: publicKey, createOptions) it may not support.
 */
export function advancedRegistrationFailureText(error, context = {}) {
    const errorName = error && typeof error === 'object' ? error.name : undefined;
    let errorMessage = error && typeof error === 'object' && typeof error.message === 'string'
        ? error.message
        : String(error);
    if (Object.hasOwn(REGISTRATION_ERROR_TEXT, errorName)) {
        errorMessage = REGISTRATION_ERROR_TEXT[errorName];
    }

    // Only a refusal from the authenticator can be about what it supports; a
    // server's answer says what it means on its own.
    const potentialIssues = AUTHENTICATOR_ERROR_NAMES.has(errorName)
        ? collectPotentialUnsupportedFeatures(context.publicKey, context.createOptions)
        : [];
    const detailMessage = potentialIssues.length
        ? ` The authenticator may not support: ${potentialIssues.join(', ')}.`
        : '';

    return `Credential registration failed: ${errorMessage}${detailMessage}`;
}

function textWarnings(json) {
    return Array.isArray(json?.warnings)
        ? json.warnings.filter(msg => typeof msg === 'string' && msg.trim().length > 0)
        : [];
}

/** A registration's success message, and its tone: a warning when the server added warnings. */
export function advancedRegisteredMessage(answer) {
    const successMessage = `Advanced registration successful! Algorithm: ${answer.algo || 'Unknown'}`;
    const warnings = textWarnings(answer);
    return warnings.length > 0
        ? { text: `${successMessage} ${warnings.join(' ')}`, tone: 'warning' }
        : { text: successMessage, tone: 'success' };
}

/**
 * The editor's text as a registration's request: the object it parses to,
 * holding publicKey with rp, user and challenge, or the sentence that says what
 * is missing (the parser's error for text that is not JSON).
 */
export function readCreationRequest(text) {
    const parsed = JSON.parse(text);

    if (!parsed.publicKey) {
        throw new Error(ADVANCED_CEREMONY_TEXT.missingPublicKey);
    }
    const { publicKey } = parsed;
    if (!publicKey.rp) {
        throw new Error(ADVANCED_CEREMONY_TEXT.missingRp);
    }
    if (!publicKey.user) {
        throw new Error(ADVANCED_CEREMONY_TEXT.missingUser);
    }
    if (!publicKey.challenge) {
        throw new Error(ADVANCED_CEREMONY_TEXT.missingChallenge);
    }
    return parsed;
}

/**
 * The record the browser keeps for a registration the server stored: the
 * server's, with the credential's ID as the browser gave it (base64url and hex)
 * and the user's name. None when the server stored nothing.
 */
export function registeredRecord(answer, credential, publicKey) {
    if (!answer.storedCredential || typeof answer.storedCredential !== 'object') {
        return null;
    }
    const rawIdBytes = bufferSourceToUint8Array(credential.rawId);
    const credentialIdFromBrowser = typeof credential.id === 'string' && credential.id.trim()
        ? credential.id.trim()
        : '';
    const credentialIdBase64Url = credentialIdFromBrowser
        || answer.storedCredential.credentialIdBase64Url
        || answer.storedCredential.credentialId
        || '';
    const credentialIdHexFromBrowser = rawIdBytes && rawIdBytes.length
        ? bytesToHex(rawIdBytes)
        : '';

    return {
        ...answer.storedCredential,
        id: credentialIdBase64Url || answer.storedCredential.id,
        credentialId: credentialIdBase64Url || answer.storedCredential.credentialId,
        credentialIdBase64Url,
        credentialIdHex: credentialIdHexFromBrowser || answer.storedCredential.credentialIdHex,
        userName: answer.storedCredential.userName || publicKey?.user?.name || '',
    };
}

function postJson(path, body) {
    return fetch(path, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body),
    });
}

/**
 * Registers a credential from the editor's text. The form's views give:
 * enforceHints(publicKey) (the attachments the hints allow; it may throw),
 * applyAttachmentPreference(options, attachments, ...sources) (the attachment
 * the browser is given) and minPinLength() (the switch, which asks for the
 * extension whatever the text says, read when the ceremony gets there). It says what it does through
 * onStart (the request checked: the last ceremony's messages may go),
 * onProgress, onWarning (the server's warnings about the request) and onResult
 * (the result panel's input, shared/ceremony-result.js). Gives
 * `{registered: true, answer, credential, credentialJson, publicKey, record}`,
 * or `{registered: false, text, context}` with the failure's sentence.
 * @param {string} text
 * @param {{
 *     enforceHints: (publicKey: Record<string, any>) => string[],
 *     applyAttachmentPreference: (
 *         options: { publicKey: PublicKeyCredentialCreationOptions },
 *         attachments: string[],
 *         ...sources: unknown[]
 *     ) => void,
 *     minPinLength: () => boolean,
 *     onStart?: () => void,
 *     onProgress?: (text: string) => void,
 *     onWarning?: (text: string) => void,
 *     onResult?: (result: CeremonyResultInput) => void,
 * }} steps
 */
export async function registerAdvancedCredential(text, {
    enforceHints,
    applyAttachmentPreference,
    minPinLength,
    onStart = () => {},
    onProgress = () => {},
    onWarning = () => {},
    onResult = () => {},
}) {
    /**
     * @type {{
     *     publicKey: Record<string, any> | null,
     *     createOptions: { publicKey: PublicKeyCredentialCreationOptions } | null,
     * }}
     */
    const context = { publicKey: null, createOptions: null };

    try {
        requireNativeJson();
        const parsed = readCreationRequest(text);
        const { publicKey } = parsed;
        context.publicKey = publicKey;

        if (minPinLength()) {
            if (!publicKey.extensions || typeof publicKey.extensions !== 'object') {
                publicKey.extensions = {};
            }
            publicKey.extensions.minPinLength = true;
        }

        const allowedAttachments = enforceHints(publicKey);

        onStart();
        onProgress(ADVANCED_CEREMONY_TEXT.registrationStarting);

        const response = await postJson('/api/advanced/register/begin', parsed);
        if (!response.ok) {
            throw new FailedResponseError(await readFailedResponse(response));
        }

        const json = await response.json();

        const warnings = textWarnings(json);
        if (warnings.length > 0) {
            onWarning(warnings.join(' '));
        }

        const optionsJson = { ...(json || {}) };
        delete optionsJson.warnings;

        // The browser reads the options, every extension it implements included.
        const createOptions = { publicKey: parseCreationOptions(optionsJson.publicKey) };
        context.createOptions = createOptions;

        applyAttachmentPreference(
            createOptions,
            allowedAttachments,
            json?.publicKey,
            publicKey,
        );

        onProgress(ADVANCED_CEREMONY_TEXT.connecting);

        // Its JSON as the browser writes it: the attachment, and every extension output in base64url.
        const { credential, json: credentialJson } = await createCredential(createOptions.publicKey);

        onProgress(ADVANCED_CEREMONY_TEXT.registrationCompleting);

        const result = await postJson('/api/advanced/register/complete', {
            ...parsed,
            __credential_response: credentialJson,
        });

        if (!result.ok) {
            const failure = await readFailedResponse(result);
            onResult({
                title: ADVANCED_CEREMONY_TEXT.lastRegistration,
                showChallenge: true,
                challengeSource: failure.challengeSource,
                challengeStatus: failure.challengeStatus,
            });
            throw new FailedResponseError(failure);
        }

        const answer = await result.json();
        onResult({
            title: ADVANCED_CEREMONY_TEXT.lastRegistration,
            showChallenge: true,
            challengeSource: answer.challengeSource,
            challengeStatus: answer.challengeStatus,
        });
        return {
            registered: true,
            answer,
            credential,
            credentialJson,
            publicKey,
            record: registeredRecord(answer, credential, publicKey),
        };
    } catch (error) {
        return { registered: false, text: advancedRegistrationFailureText(error, context), context };
    }
}
