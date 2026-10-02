// What the registration view is built from: the decoded attestation object, its
// certificates (and which of them the view lists), the authenticator data, its
// hex and SHA-256. DOM-free, and every function takes the state it reads and
// writes: one per credential shown. ./prepare.js fills a state from a record
// and the decoder, ./state-snapshot.js from a saved snapshot and back.
import {
    deriveCertificateIdentity,
    normaliseCertificateEntryForModal,
} from '../certificates/core.js';

/**
 * What the view says about the two decodes: the values decoded, and why one failed ('' when it did not).
 * @typedef {object} DetailPreparation
 * @property {string} attestationObjectValue
 * @property {string} attestationDecodeError
 * @property {string} authenticatorDataValue
 * @property {string} authenticatorDecodeError
 */

/**
 * One credential's registration as the view reads it: JSON the decoder answered
 * (or a snapshot kept), and the authenticator data's hex and SHA-256 ('' for none).
 * @typedef {object} RegistrationState
 * @property {Record<string, any> | null} attestationObject
 * @property {Array<Record<string, any>>} attestationCertificates
 * @property {number[]} visibleAttestationCertificateIndices
 * @property {Record<string, any> | null} authenticatorData
 * @property {string} authenticatorDataHash
 * @property {string} authenticatorDataHex
 */

/**
 * What a registration not yet decoded is read from, as a record holds it.
 * @typedef {object} RegistrationSources
 * @property {any} [attestationObjectValue]
 * @property {any} [attestationObjectDecoded]
 * @property {any} [authenticatorDataValue]
 * @property {any} [fallbackCertificates]
 * @property {any} [relyingPartyInfo]
 * @property {boolean} [preferFallbackCertificates]
 */

/**
 * The decoder (POST /api/codec): JSON for base64url bytes.
 * @typedef {(value: string) => Promise<any>} Decode
 */

/** @type {Readonly<DetailPreparation>} */
export const EMPTY_DETAIL_PREPARATION = Object.freeze({
    attestationObjectValue: '',
    attestationDecodeError: '',
    authenticatorDataValue: '',
    authenticatorDecodeError: '',
});

/**
 * An empty state.
 * @returns {RegistrationState}
 */
export function createRegistrationState() {
    return {
        attestationObject: null,
        attestationCertificates: [],
        visibleAttestationCertificateIndices: [],
        authenticatorData: null,
        authenticatorDataHash: '',
        authenticatorDataHex: '',
    };
}

/**
 * Empties `state` in place (a view may hold on to it).
 * @param {RegistrationState} state
 */
export function resetRegistrationState(state) {
    Object.assign(state, createRegistrationState());
}

/** @param {RegistrationState} state */
export function addStateCertificate(state, entry) {
    const normalised = normaliseCertificateEntryForModal(entry);
    if (!normalised) {
        return;
    }

    const identity = deriveCertificateIdentity(normalised);
    const existing = state.attestationCertificates;

    if (identity) {
        const existingIndex = existing.findIndex(item => deriveCertificateIdentity(item) === identity);
        if (existingIndex !== -1) {
            const currentEntry = existing[existingIndex];
            const currentParsed = currentEntry && typeof currentEntry === 'object' && currentEntry.parsedX5c
                && typeof currentEntry.parsedX5c === 'object'
                ? currentEntry.parsedX5c
                : null;
            // normaliseCertificateEntryForModal always gives parsedX5c an object.
            const newParsed = normalised.parsedX5c;
            const currentHasError = Boolean(currentParsed && currentParsed.parseError);
            const newHasError = Boolean(newParsed && newParsed.parseError);

            if (currentHasError && !newHasError) {
                existing[existingIndex] = normalised;
            }
            return;
        }
    } else {
        // Without an identity the entry has no raw bytes either (they would be
        // its identity), so only its PEM can match another's.
        const duplicate = existing.some(item => Boolean(item.pem && normalised.pem && item.pem === normalised.pem));

        if (duplicate) {
            return;
        }
    }

    existing.push(normalised);
}

/** @param {RegistrationState} state */
export function addStateCertificates(state, entries) {
    if (!entries) {
        return;
    }
    if (Array.isArray(entries)) {
        entries.forEach(entry => addStateCertificate(state, entry));
    } else {
        addStateCertificate(state, entries);
    }
}

/**
 * The certificates the view lists, in its order.
 * @param {RegistrationState} state
 */
export function visibleStateCertificates(state) {
    const indices = Array.isArray(state.visibleAttestationCertificateIndices)
        ? state.visibleAttestationCertificateIndices
        : [];

    return indices
        .map(idx => state.attestationCertificates[idx])
        .filter(entry => entry && typeof entry === 'object');
}
