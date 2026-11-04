// The parts of a saved credential's registration the Codec can decode, each as
// the record spells it ('' for a part it does not keep whole): the browser's
// response, its attestation object, client data and authenticator data, and each
// certificate the details list. Only values kept whole are read: the browser's
// response (the record's, or its snapshot's, which keeps it whole or not at
// all), the record's own fields and the relying party's hex, and the listed
// certificates' own encodings. The copies earlier releases cut short in a
// snapshot's state (its attestation object and authenticator data) are never
// read. DOM-free: the details' levels hand these to the Codec.
import { visibleStateCertificates } from '../registration/state.js';

/** @import { RegistrationState } from '../registration/state.js' */

/**
 * @typedef {{
 *   response: string,
 *   attestationObject: string,
 *   clientDataJSON: string,
 *   authenticatorData: string,
 *   certificates: string[],
 * }} CodecPayloads
 */

const textOf = value => (typeof value === 'string' ? value.trim() : '');
const objectOf = value => (value && typeof value === 'object' && !Array.isArray(value) ? value : null);
const firstText = (...values) => values.map(textOf).find(Boolean) || '';

// A certificate the details list: its PEM, else its DER in base64, else its hex.
function certificatePayload(entry) {
    const parsed = objectOf(entry.parsedX5c) || {};
    return firstText(entry.pem, parsed.pem, parsed.derBase64, entry.derBase64, entry.raw);
}

/**
 * @param {Record<string, any>} cred The record the details were composed from.
 * @param {{ snapshotResponse?: { credential: Record<string, any> | null, relyingParty: Record<string, any> | null } | null, state: RegistrationState }} sources
 * @returns {CodecPayloads}
 */
export function codecPayloads(cred, { snapshotResponse = null, state }) {
    const credential = objectOf(cred.registrationResponse) || objectOf(snapshotResponse?.credential);
    const response = objectOf(credential?.response);
    const parts = response || credential || {};
    const relyingParties = [objectOf(cred.relyingParty), objectOf(snapshotResponse?.relyingParty)]
        .filter(Boolean);
    const relyingPartyHex = relyingParties.flatMap(party => [
        party.authenticatorData,
        objectOf(party.registrationData)?.authenticatorData,
    ]);
    return {
        response: response ? JSON.stringify(credential, null, 2) : '',
        attestationObject: firstText(parts.attestationObject, cred.attestationObject),
        clientDataJSON: firstText(parts.clientDataJSON, cred.clientDataJSON),
        authenticatorData: firstText(parts.authenticatorData, cred.authenticatorData, ...relyingPartyHex),
        certificates: visibleStateCertificates(state).map(certificatePayload),
    };
}
