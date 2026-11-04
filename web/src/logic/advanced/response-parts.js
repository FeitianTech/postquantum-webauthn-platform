// The parts of a ceremony's response the Codec reads, as the browser wrote
// them in its JSON (base64url), each with its word for the result's row of
// buttons: the whole response first (the decoder reads a PublicKeyCredential
// member by member), then its attestation object, client data and
// authenticator data, those it has. A signature is left out, since the decoder
// has no reading for one alone (it shows inside the whole response), and so is
// a user handle, bytes the relying party chose. DOM-free.

/** @typedef {{ part: string, label: string, payload: string }} ResponsePart */

const PARTS = [
    { key: 'attestationObject', part: 'attestation object', label: 'Attestation object' },
    { key: 'clientDataJSON', part: 'client data', label: 'Client data' },
    { key: 'authenticatorData', part: 'authenticator data', label: 'Authenticator data' },
];

/**
 * @param {Record<string, any> | null | undefined} credentialJson The browser's JSON of its credential.
 * @returns {ResponsePart[]}
 */
export function responseParts(credentialJson) {
    const response = credentialJson?.response;
    if (!response || typeof response !== 'object') {
        return [];
    }
    /** @type {ResponsePart[]} */
    const parts = [{ part: 'response', label: 'Response', payload: JSON.stringify(credentialJson, null, 2) }];
    PARTS.forEach(({ key, part, label }) => {
        const value = typeof response[key] === 'string' ? response[key].trim() : '';
        if (value) {
            parts.push({ part, label, payload: value });
        }
    });
    return parts;
}
