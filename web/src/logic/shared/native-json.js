// The browser's own WebAuthn JSON (WebAuthn Level 3): a begin answer's options
// read by PublicKeyCredential.parseCreationOptionsFromJSON and
// parseRequestOptionsFromJSON, the credential written by its toJSON(). Chrome
// and Edge 129, Firefox 119 and Safari 18.4 have all three; a browser without
// them runs no ceremony and is asked to update. With no DOM: it reads only the
// scope it is given, the page's global by default.

export const UPDATE_BROWSER_TEXT =
    'This browser cannot run WebAuthn ceremonies here: update it to Chrome or Edge 129, Firefox 119, Safari 18.4 or later.';

/** Thrown before anything is asked of the server when the browser lacks the methods. */
export class UnsupportedBrowserError extends Error {
    constructor() {
        super(UPDATE_BROWSER_TEXT);
        this.name = 'UnsupportedBrowserError';
    }
}

/** Whether the browser reads options from JSON and writes credentials as JSON itself. */
export function nativeJsonSupported(scope = globalThis) {
    const credentialClass = scope.PublicKeyCredential;
    return typeof credentialClass === 'function'
        && typeof credentialClass.parseCreationOptionsFromJSON === 'function'
        && typeof credentialClass.parseRequestOptionsFromJSON === 'function'
        && typeof credentialClass.prototype?.toJSON === 'function';
}

/** Throws UnsupportedBrowserError unless the browser has the three methods. */
export function requireNativeJson(scope = globalThis) {
    if (!nativeJsonSupported(scope)) {
        throw new UnsupportedBrowserError();
    }
    return scope.PublicKeyCredential;
}

/** A begin answer's publicKey (creation options as JSON) as navigator.credentials.create() takes it. */
export function parseCreationOptions(publicKeyJson, scope = globalThis) {
    return requireNativeJson(scope).parseCreationOptionsFromJSON(publicKeyJson);
}

/** A begin answer's publicKey (request options as JSON) as navigator.credentials.get() takes it. */
export function parseRequestOptions(publicKeyJson, scope = globalThis) {
    return requireNativeJson(scope).parseRequestOptionsFromJSON(publicKeyJson);
}

/** Asks the authenticator for a new credential: gives it, and its JSON as the server is sent it. */
export async function createCredential(publicKey, scope = globalThis) {
    const credential = await scope.navigator.credentials.create({ publicKey });
    return { credential, json: credential.toJSON() };
}

/** Asks the authenticator for an assertion: gives it, and its JSON as the server is sent it. */
export async function getAssertion(publicKey, scope = globalThis) {
    const credential = await scope.navigator.credentials.get({ publicKey });
    return { credential, json: credential.toJSON() };
}
