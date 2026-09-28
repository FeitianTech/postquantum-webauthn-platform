// What the registration view is built from: the decoded attestation object, its
// certificates (and which of them the view lists), the authenticator data, its
// hex and SHA-256. DOM-free, and every function takes the state it reads and
// writes: the current UI keeps one (./state.js, which its certificate and
// authenticator-data views read when their buttons are pressed), the new UI one
// per credential it shows.
import {
    base64UrlToHex,
    bytesToHex,
    hexToUint8Array,
} from '../../shared/utils/binary.js';
import {base64ToBytes, base64UrlToBytes} from '../../shared/utils/base64.js';
import {
    deriveCertificateIdentity,
    normaliseCertificateEntryForModal,
} from './certificate-core.js';
import {cloneJson} from './data-utils.js';

export const EMPTY_DETAIL_PREPARATION = Object.freeze({
    attestationObjectValue: '',
    attestationDecodeError: '',
    authenticatorDataValue: '',
    authenticatorDecodeError: '',
});

/** An empty state. */
export function createRegistrationState() {
    const state = {};
    resetRegistrationState(state);
    return state;
}

/** Empties `state` in place (a view may hold on to it). */
export function resetRegistrationState(state) {
    state.attestationObject = null;
    state.attestationCertificates = [];
    state.visibleAttestationCertificateIndices = [];
    state.authenticatorData = null;
    state.authenticatorDataHash = '';
    state.authenticatorDataHex = '';
}

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

/** The certificates the view lists, in its order. */
export function visibleStateCertificates(state) {
    const indices = Array.isArray(state.visibleAttestationCertificateIndices)
        ? state.visibleAttestationCertificateIndices
        : [];

    return indices
        .map(idx => state.attestationCertificates[idx])
        .filter(entry => entry && typeof entry === 'object');
}

/** The authenticator data's hex and SHA-256, from whichever spelling of its bytes reads. */
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

    // The first candidate that reads gives the hex: hex text, else base64url, else base64.
    for (const candidate of hexCandidates) {
        const normalized = candidate.replace(/[^0-9a-f]/gi, '').toLowerCase();
        if (!normalized || normalized.length % 2 !== 0) {
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
 * the authenticator data through `decode` (POST /api/decode), else what the
 * record holds already decoded; its certificates, else the relying party's.
 * Gives what the view says about the two decodes.
 */
export async function prepareRegistrationState(state, options = {}, { decode } = {}) {
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
            attestationDecodeError = error?.message || 'Failed to decode attestationObject.';
        }
    }

    const decodedObject = attestationObjectDecoded && typeof attestationObjectDecoded === 'object'
        ? attestationObjectDecoded
        : null;
    if (!state.attestationObject && decodedObject) {
        state.attestationObject = decodedObject;
        const attStmt = decodedObject.attStmt || decodedObject.att_statement || null;
        if (
            attStmt
            && typeof attStmt === 'object'
            && !fallbackCertificatesAvailable
        ) {
            addStateCertificates(state, attStmt.x5c || attStmt.X5C || []);
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
            authenticatorDecodeError = error?.message || 'Failed to decode authenticatorData.';
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

/** A copy of `state` as a registration snapshot keeps it (`schemaVersion` 2's `state`). */
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

/** Fills `state` from a saved snapshot, as it was captured; gives what it said about the decodes. */
export function applyRegistrationSnapshot(state, snapshot) {
    if (!snapshot || typeof snapshot !== 'object') {
        return;
    }

    const stateSource = snapshot.state && typeof snapshot.state === 'object'
        ? snapshot.state
        : snapshot;

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
