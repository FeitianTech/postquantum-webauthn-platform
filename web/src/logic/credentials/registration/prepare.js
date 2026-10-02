// A registration state filled for a registration not yet decoded: the
// attestation object and the authenticator data through the decoder, their
// certificates, and the authenticator data's hex and SHA-256. DOM-free.
import {
    base64UrlToHex,
    bytesToHex,
    hexToUint8Array,
} from '../../shared/bytes.js';
import {base64ToBytes, base64UrlToBytes} from '../../shared/base64.js';
import {addStateCertificates, resetRegistrationState} from './state.js';

/** @import { Decode, DetailPreparation, RegistrationSources, RegistrationState } from './state.js' */

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
