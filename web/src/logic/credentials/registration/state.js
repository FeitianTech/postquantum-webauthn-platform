// What the registration view is built from: the decoded attestation object, its
// certificates (and which of them the view lists), the authenticator data, its
// hex and SHA-256. DOM-free, and every function takes the state it reads and
// writes: one per credential shown.
import {
    base64UrlToHex,
    bytesToHex,
    hexToUint8Array,
} from '../../shared/bytes.js';
import {base64ToBytes, base64UrlToBytes} from '../../shared/base64.js';
import {
    deriveCertificateIdentity,
    normaliseCertificateEntryForModal,
} from '../certificates/core.js';
import {cloneJson} from '../../shared/json.js';

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

/**
 * The authenticator data's hex and SHA-256, from whichever spelling of its bytes reads.
 * @param {RegistrationState} state
 * @returns {Promise<string>}
 */
export async function hashAuthenticatorData(state) {
    state.authenticatorDataHash = '';
    state.authenticatorDataHex = '';

    const data = state.authenticatorData;
    if (!data) {
        return '';
    }

    const hexCandidates = new Set();
    const base64UrlCandidates = new Set();
    const base64Candidates = new Set();

    const addCandidate = (collection, value) => {
        if (typeof value !== 'string') {
            return;
        }
        const trimmed = value.trim();
        if (trimmed) {
            collection.add(trimmed);
        }
    };

    if (typeof data === 'string') {
        addCandidate(hexCandidates, data);
        addCandidate(base64UrlCandidates, data);
        addCandidate(base64Candidates, data);
    } else if (typeof data === 'object') {
        ['raw', 'hex', 'rawHex', 'raw_hex', 'hexValue', 'value'].forEach(key => {
            addCandidate(hexCandidates, data[key]);
        });
        ['base64url', 'base64Url'].forEach(key => {
            addCandidate(base64UrlCandidates, data[key]);
        });
        addCandidate(base64Candidates, data.base64);
    }

    let bytes = null;

    // The first candidate that reads gives the hex: hex text (spaces and colons
    // aside), else base64url, else base64. Text with other characters is not
    // hex: base64url text is read as base64url below.
    for (const candidate of hexCandidates) {
        const normalized = candidate.replace(/[\s:]/g, '').toLowerCase();
        if (!/^[0-9a-f]+$/.test(normalized) || normalized.length % 2 !== 0) {
            continue;
        }
        state.authenticatorDataHex = normalized;
        bytes = hexToUint8Array(normalized);
        break;
    }

    // base64url, and a value under a `base64` key standard base64: each read
    // strictly, and a candidate that does not decode is passed over.
    const decodeFirst = (candidates, decode) => {
        for (const candidate of candidates) {
            let converted = null;
            try {
                converted = decode(candidate);
            } catch (error) {
                converted = null;
            }
            if (converted && converted.length) {
                state.authenticatorDataHex = bytesToHex(converted);
                return converted;
            }
        }
        return null;
    };

    if (!bytes) {
        bytes = decodeFirst(base64UrlCandidates, base64UrlToBytes);
    }

    if (!bytes) {
        bytes = decodeFirst(base64Candidates, base64ToBytes);
    }

    if (!bytes || !bytes.length) {
        return '';
    }

    const crypto = globalThis.crypto;
    if (!crypto || !crypto.subtle || typeof crypto.subtle.digest !== 'function') {
        return '';
    }

    try {
        const digestBuffer = await crypto.subtle.digest('SHA-256', bytes);
        const hashHex = bytesToHex(new Uint8Array(digestBuffer));
        state.authenticatorDataHash = hashHex;
        return hashHex;
    } catch (error) {
        state.authenticatorDataHash = '';
        return '';
    }
}

/**
 * Fills `state` for a registration not yet decoded: the attestation object and
 * the authenticator data through `decode` (POST /api/codec), else what the
 * record holds already decoded; its certificates, else the relying party's.
 * Gives what the view says about the two decodes.
 * @param {RegistrationState} state
 * @param {RegistrationSources | null} [options]
 * @param {{ decode: Decode }} [steps] Only a value to decode calls `decode`: a call with none may leave it out.
 * @returns {Promise<DetailPreparation>}
 */
export async function prepareRegistrationState(
    state,
    options = {},
    { decode } = /** @type {{ decode: Decode }} */ ({}),
) {
    const {
        attestationObjectValue = '',
        attestationObjectDecoded = null,
        authenticatorDataValue = '',
        fallbackCertificates = [],
        relyingPartyInfo = null,
        preferFallbackCertificates = false,
    } = options || {};

    resetRegistrationState(state);

    const attestationValue = typeof attestationObjectValue === 'string'
        ? attestationObjectValue.trim()
        : '';
    const authenticatorValue = typeof authenticatorDataValue === 'string'
        ? authenticatorDataValue.trim()
        : '';

    let attestationDecodeError = '';
    let authenticatorDecodeError = '';

    if (fallbackCertificates) {
        addStateCertificates(state, fallbackCertificates);
    }

    const fallbackCertificatesAvailable = preferFallbackCertificates
        && state.attestationCertificates.length > 0;

    if (attestationValue) {
        try {
            const decoded = await decode(attestationValue);
            const attestationData = decoded?.data?.attestationObject || decoded?.data || null;
            if (attestationData && typeof attestationData === 'object') {
                state.attestationObject = attestationData;
                if (
                    attestationData.attStmt
                    && typeof attestationData.attStmt === 'object'
                    && !fallbackCertificatesAvailable
                ) {
                    addStateCertificates(state, attestationData.attStmt.x5c);
                }
            }
            if (decoded?.data?.authenticatorData) {
                state.authenticatorData = decoded.data.authenticatorData;
            }
        } catch (error) {
            attestationDecodeError = decodeFailure(error, 'Failed to decode attestationObject.');
        }
    }

    const decodedObject = attestationObjectDecoded && typeof attestationObjectDecoded === 'object'
        ? attestationObjectDecoded
        : null;
    if (!state.attestationObject && decodedObject) {
        state.attestationObject = decodedObject;
        const attStmt = decodedObject.attStmt || null;
        if (
            attStmt
            && typeof attStmt === 'object'
            && !fallbackCertificatesAvailable
        ) {
            addStateCertificates(state, attStmt.x5c || []);
        }
    }

    if (!state.attestationCertificates.length && relyingPartyInfo?.attestationCertificate) {
        addStateCertificates(state, relyingPartyInfo.attestationCertificate);
    }
    if (!state.attestationCertificates.length && Array.isArray(relyingPartyInfo?.attestationCertificates)) {
        addStateCertificates(state, relyingPartyInfo.attestationCertificates);
    }

    if (!state.authenticatorData && authenticatorValue) {
        try {
            const decodedAuth = await decode(authenticatorValue);
            if (decodedAuth?.data) {
                state.authenticatorData = decodedAuth.data;
            }
        } catch (error) {
            authenticatorDecodeError = decodeFailure(error, 'Failed to decode authenticatorData.');
        }
    }

    if (!state.authenticatorData && authenticatorValue) {
        const fallback = { base64url: authenticatorValue };
        try {
            fallback.raw = base64UrlToHex(authenticatorValue);
        } catch (error) {
            fallback.raw = authenticatorValue;
        }
        state.authenticatorData = fallback;
    }

    await hashAuthenticatorData(state);

    return {
        attestationObjectValue: attestationValue,
        attestationDecodeError,
        authenticatorDataValue: authenticatorValue,
        authenticatorDecodeError,
    };
}

/**
 * @param {any} error
 * @param {string} fallback
 * @returns {string}
 */
function decodeFailure(error, fallback) {
    return error?.message || fallback;
}

/** @returns {DetailPreparation} */
export function normaliseDetailPreparationSnapshot(value) {
    if (!value || typeof value !== 'object') {
        return { ...EMPTY_DETAIL_PREPARATION };
    }
    return {
        attestationObjectValue: typeof value.attestationObjectValue === 'string' ? value.attestationObjectValue : '',
        attestationDecodeError: typeof value.attestationDecodeError === 'string' ? value.attestationDecodeError : '',
        authenticatorDataValue: typeof value.authenticatorDataValue === 'string' ? value.authenticatorDataValue : '',
        authenticatorDecodeError: typeof value.authenticatorDecodeError === 'string' ? value.authenticatorDecodeError : '',
    };
}

/**
 * A copy of `state` as a registration snapshot keeps it (`schemaVersion` 2's `state`).
 * @param {RegistrationState} state
 * @param {DetailPreparation} [detailPreparation]
 */
export function captureRegistrationState(state, detailPreparation = EMPTY_DETAIL_PREPARATION) {
    const certificatesClone = cloneJson(state.attestationCertificates) || [];
    const visibleIndices = Array.isArray(state.visibleAttestationCertificateIndices)
        ? [...state.visibleAttestationCertificateIndices]
        : [];

    return {
        detailPreparation: normaliseDetailPreparationSnapshot(detailPreparation),
        attestationObject: cloneJson(state.attestationObject),
        attestationCertificates: Array.isArray(certificatesClone) ? certificatesClone : [],
        visibleAttestationCertificateIndices: visibleIndices,
        authenticatorData: cloneJson(state.authenticatorData),
        authenticatorDataHex: typeof state.authenticatorDataHex === 'string'
            ? state.authenticatorDataHex
            : '',
        authenticatorDataHash: typeof state.authenticatorDataHash === 'string'
            ? state.authenticatorDataHash
            : '',
    };
}

/**
 * Fills `state` from a saved snapshot's state (an object: both callers check), as it
 * was captured; gives what it said about the decodes.
 * @param {RegistrationState} state
 * @param {Record<string, any>} stateSource
 * @returns {DetailPreparation}
 */
export function applyRegistrationSnapshot(state, stateSource) {
    const attObj = cloneJson(stateSource.attestationObject);
    state.attestationObject = attObj && typeof attObj === 'object' ? attObj : null;

    const certificatesClone = cloneJson(stateSource.attestationCertificates);
    state.attestationCertificates = Array.isArray(certificatesClone)
        ? certificatesClone
        : [];

    const indices = Array.isArray(stateSource.visibleAttestationCertificateIndices)
        ? [...stateSource.visibleAttestationCertificateIndices]
        : [];
    state.visibleAttestationCertificateIndices = indices;

    const authDataClone = cloneJson(stateSource.authenticatorData);
    state.authenticatorData = authDataClone && typeof authDataClone === 'object'
        ? authDataClone
        : null;

    state.authenticatorDataHex = typeof stateSource.authenticatorDataHex === 'string'
        ? stateSource.authenticatorDataHex
        : '';
    state.authenticatorDataHash = typeof stateSource.authenticatorDataHash === 'string'
        ? stateSource.authenticatorDataHash
        : '';

    if (!state.visibleAttestationCertificateIndices.length && state.attestationCertificates.length) {
        state.visibleAttestationCertificateIndices = state.attestationCertificates.map((_, index) => index);
    }

    if (state.authenticatorData && typeof state.authenticatorData === 'object') {
        if (state.authenticatorDataHex && !state.authenticatorData.raw) {
            state.authenticatorData.raw = state.authenticatorDataHex;
        }
    }

    return stateSource.detailPreparation
        ? normaliseDetailPreparationSnapshot(stateSource.detailPreparation)
        : { ...EMPTY_DETAIL_PREPARATION };
}
