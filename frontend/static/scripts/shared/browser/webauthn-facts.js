// What the browser answers about WebAuthn. Every fact is in one of four states:
// the browser said yes, said no, has no way to ask (the method is missing), or the
// question could not be answered (the call threw, or the answer was not a boolean).

import { attempt, describeError, describeValue } from './probe.js';

export const STATE_TEXT = {
    yes: 'Yes',
    no: 'No',
    unavailable: 'Not available in this browser',
    undetermined: 'Could not be determined',
};

export const WEBAUTHN_FACTS = [
    { id: 'secureContext', label: 'Secure context', api: 'window.isSecureContext' },
    { id: 'webauthnApi', label: 'WebAuthn API', api: 'PublicKeyCredential, navigator.credentials' },
    {
        id: 'conditionalMediation',
        label: 'Passkey autofill (conditional mediation)',
        api: 'PublicKeyCredential.isConditionalMediationAvailable()',
    },
    {
        id: 'parseCreationOptionsFromJSON',
        label: 'Read registration options from JSON',
        api: 'PublicKeyCredential.parseCreationOptionsFromJSON()',
    },
    {
        id: 'parseRequestOptionsFromJSON',
        label: 'Read authentication options from JSON',
        api: 'PublicKeyCredential.parseRequestOptionsFromJSON()',
    },
    { id: 'toJSON', label: 'Write a credential as JSON', api: 'PublicKeyCredential.prototype.toJSON()' },
];

export const AUTHENTICATOR_FACTS = [
    {
        id: 'userVerifyingPlatformAuthenticator',
        label: 'Built-in authenticator that verifies the user',
        api: 'PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()',
    },
    {
        id: 'hybridTransport',
        label: 'A phone or tablet, over hybrid',
        api: 'getClientCapabilities().hybridTransport',
    },
];

// The ClientCapability values WebAuthn Level 3 defines, in the spec's order.
export const CLIENT_CAPABILITY_LABELS = {
    conditionalCreate: 'Create a passkey without a prompt of its own (conditional create)',
    conditionalGet: 'Passkey autofill (conditional get)',
    hybridTransport: 'Use a phone or tablet (hybrid transport)',
    passkeyPlatformAuthenticator: 'Passkeys on this device or a phone (passkey platform authenticator)',
    userVerifyingPlatformAuthenticator: 'Built-in authenticator that verifies the user',
    relatedOrigins: 'Related origin requests',
    signalAllAcceptedCredentials: 'Tell the authenticator which credentials the site still accepts',
    signalCurrentUserDetails: "Tell the authenticator the user's current name",
    signalUnknownCredential: 'Tell the authenticator a credential the site does not know',
};

const EXTENSION_PREFIX = 'extension:';
const NO_WEBAUTHN = 'The WebAuthn API is not available on this page.';
const NO_CLIENT_CAPABILITIES =
    'getClientCapabilities() is a WebAuthn Level 3 feature this browser does not offer.';

function undetermined(note) {
    return { state: 'undetermined', note };
}

function booleanFact(value) {
    if (value === true) {
        return { state: 'yes' };
    }
    if (value === false) {
        return { state: 'no' };
    }
    return undetermined(`The browser answered ${describeValue(value)}, not true or false.`);
}

function offers(read) {
    const result = attempt(read);
    if (result.error) {
        return undetermined(result.error);
    }
    return { state: typeof result.value === 'function' ? 'yes' : 'unavailable' };
}

async function ask(owner, method) {
    const read = attempt(() => owner[method]);
    if (read.error) {
        return undetermined(read.error);
    }
    if (typeof read.value !== 'function') {
        return { state: 'unavailable' };
    }
    try {
        return booleanFact(await read.value.call(owner));
    } catch (error) {
        return undetermined(describeError(error));
    }
}

function secureContextFact(scope) {
    const read = attempt(() => scope.isSecureContext);
    if (read.error) {
        return undetermined(read.error);
    }
    if (typeof read.value !== 'boolean') {
        return { state: 'unavailable' };
    }
    return read.value ? { state: 'yes' } : { state: 'no', note: 'WebAuthn works only over HTTPS or on localhost.' };
}

function webauthnApiFact(scope, secureContext) {
    const publicKeyCredential = attempt(() => scope.PublicKeyCredential);
    const credentials = attempt(() => scope.navigator?.credentials);
    const error = publicKeyCredential.error ?? credentials.error;
    if (error) {
        return undetermined(error);
    }
    const missing = [];
    if (typeof publicKeyCredential.value !== 'function') {
        missing.push('PublicKeyCredential');
    }
    if (typeof credentials.value?.create !== 'function' || typeof credentials.value?.get !== 'function') {
        missing.push('navigator.credentials.create() and get()');
    }
    if (missing.length === 0) {
        return { state: 'yes' };
    }
    const why = secureContext.state === 'no' ? ' Browsers offer WebAuthn only in a secure context.' : '';
    return { state: 'unavailable', note: `Missing: ${missing.join('; ')}.${why}` };
}

function describeCapability(key, value) {
    const fact = booleanFact(value);
    if (key.startsWith(EXTENSION_PREFIX)) {
        return { key, kind: 'extension', label: key.slice(EXTENSION_PREFIX.length), ...fact };
    }
    if (Object.prototype.hasOwnProperty.call(CLIENT_CAPABILITY_LABELS, key)) {
        return { key, kind: 'defined', label: CLIENT_CAPABILITY_LABELS[key], ...fact };
    }
    return { key, kind: 'unrecognised', label: key, ...fact };
}

async function readClientCapabilities(publicKeyCredential) {
    const nothing = { returned: null, capabilities: [], omitted: [] };
    if (typeof publicKeyCredential !== 'function') {
        return { state: 'unavailable', note: NO_WEBAUTHN, ...nothing };
    }
    const method = attempt(() => publicKeyCredential.getClientCapabilities);
    if (method.error) {
        return { ...undetermined(method.error), ...nothing };
    }
    if (typeof method.value !== 'function') {
        return { state: 'unavailable', note: NO_CLIENT_CAPABILITIES, ...nothing };
    }

    let returned;
    try {
        returned = await method.value.call(publicKeyCredential);
    } catch (error) {
        return { ...undetermined(describeError(error)), ...nothing };
    }
    if (!returned || typeof returned !== 'object') {
        return { ...undetermined(`The browser answered ${describeValue(returned)}, not a record.`), ...nothing };
    }

    const entries = returned instanceof Map ? Array.from(returned.entries()) : Object.entries(returned);
    const keys = new Set(entries.map(([key]) => key));
    return {
        state: 'yes',
        returned: Object.fromEntries(entries),
        capabilities: entries.map(([key, value]) => describeCapability(String(key), value)),
        // The spec: "When a capability does not exist as a key, the availability of
        // the client feature is not known."
        omitted: Object.keys(CLIENT_CAPABILITY_LABELS).filter(key => !keys.has(key)),
    };
}

function hybridTransportFact(clientCapabilities) {
    if (clientCapabilities.state !== 'yes') {
        return { state: clientCapabilities.state, note: clientCapabilities.note };
    }
    const entry = clientCapabilities.capabilities.find(capability => capability.key === 'hybridTransport');
    if (!entry) {
        return undetermined('getClientCapabilities() did not include hybridTransport, so its availability is not known.');
    }
    return entry.note ? { state: entry.state, note: entry.note } : { state: entry.state };
}

export async function gatherWebAuthnFacts(scope = globalThis) {
    const secureContext = secureContextFact(scope);
    const publicKeyCredential = attempt(() => scope.PublicKeyCredential).value;
    const webauthnApi = webauthnApiFact(scope, secureContext);
    const withoutWebAuthn = { state: 'unavailable', note: NO_WEBAUTHN };
    const hasPublicKeyCredential = typeof publicKeyCredential === 'function';

    const [conditionalMediation, userVerifyingPlatformAuthenticator, clientCapabilities] = await Promise.all([
        hasPublicKeyCredential ? ask(publicKeyCredential, 'isConditionalMediationAvailable') : withoutWebAuthn,
        hasPublicKeyCredential
            ? ask(publicKeyCredential, 'isUserVerifyingPlatformAuthenticatorAvailable')
            : withoutWebAuthn,
        readClientCapabilities(publicKeyCredential),
    ]);

    const offered = read => (hasPublicKeyCredential ? offers(read) : withoutWebAuthn);
    return {
        facts: {
            secureContext,
            webauthnApi,
            conditionalMediation,
            parseCreationOptionsFromJSON: offered(() => publicKeyCredential.parseCreationOptionsFromJSON),
            parseRequestOptionsFromJSON: offered(() => publicKeyCredential.parseRequestOptionsFromJSON),
            toJSON: offered(() => publicKeyCredential.prototype.toJSON),
            userVerifyingPlatformAuthenticator,
            hybridTransport: hybridTransportFact(clientCapabilities),
        },
        clientCapabilities,
    };
}
