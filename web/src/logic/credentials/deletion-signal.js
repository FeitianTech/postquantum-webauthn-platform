// Telling the browser that saved credentials the person deleted here are gone,
// with WebAuthn's Signal API (PublicKeyCredential.signalUnknownCredential), so
// its passkey manager may remove them too. Only after such a deletion, never on
// a server's answer that it does not know a credential: this site keeps
// credentials in each browser's own storage, so one this browser lacks may be
// another browser's, and a synced passkey the signal hides is hidden on every
// device. A browser without the method, or one that refuses, changes nothing
// the page says. With no DOM: it reads only the scope it is given, the page's
// global by default.
import { bytesToBase64Url } from '../shared/base64.js';
import { bytesToHex, hexToUint8Array } from '../shared/bytes.js';
import { getCredentialIdHex } from './record-fields.js';

/** What the delete questions add where the browser will be told. */
export const SIGNAL_TEXT = {
    one: 'This browser will also be told the credential is gone, so its passkey manager may remove it.',
    all: 'This browser will also be told the credentials are gone, so its passkey manager may remove them.',
};

/**
 * Whether this browser can be told a credential is gone.
 * @param {any} [scope]
 * @returns {boolean}
 */
export function canSignalDeletion(scope = globalThis) {
    return typeof scope.PublicKeyCredential?.signalUnknownCredential === 'function';
}

/**
 * @param {string} text
 * @param {any} scope
 */
async function sha256Hex(text, scope) {
    const digest = await scope.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return bytesToHex(new Uint8Array(digest));
}

/**
 * The RP ID a saved credential is for, as this page can name it. The record
 * keeps it as its SHA-256, the rpIdHash of the registration's authenticator
 * data: it is the one of the page's host and the domains above it with that
 * hash, else the page's host.
 * @param {Record<string, any>} credential
 * @param {string} host
 * @param {any} [scope]
 * @returns {Promise<string>}
 */
export async function credentialRpId(credential, host, scope = globalThis) {
    const kept = String(credential.properties?.rpIdHash || credential.relyingParty?.rpIdHash || '').toLowerCase();
    const labels = host.split('.');
    for (let index = 0; kept && index < labels.length; index += 1) {
        const candidate = labels.slice(index).join('.');
        if (await sha256Hex(candidate, scope) === kept) {
            return candidate;
        }
    }
    return host;
}

/**
 * Tells the browser that a credential this page has just deleted is gone, where
 * it can be told: signalUnknownCredential({ rpId, credentialId }), with the
 * credential's RP ID and its ID in base64url. Never rejects.
 * @param {Record<string, any>} credential
 * @param {any} [scope]
 * @returns {Promise<boolean>} whether the browser took it
 */
export async function signalDeletedCredential(credential, scope = globalThis) {
    const credentialIdHex = getCredentialIdHex(credential);
    if (!credentialIdHex || !canSignalDeletion(scope)) {
        return false;
    }
    try {
        const rpId = await credentialRpId(credential, scope.location.hostname, scope);
        const credentialId = bytesToBase64Url(/** @type {Uint8Array} */ (hexToUint8Array(credentialIdHex)));
        await scope.PublicKeyCredential.signalUnknownCredential({ rpId, credentialId });
        return true;
    } catch {
        // A browser that refuses (an RP ID it will not take here) is told nothing more.
        return false;
    }
}
