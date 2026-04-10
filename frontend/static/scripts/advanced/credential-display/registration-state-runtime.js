import {
    base64ToUint8Array,
    base64UrlToHex,
    base64UrlToUint8Array,
    bytesToHex,
    hexToUint8Array,
} from '../../shared/utils/binary.js';
import {addCertificatesToRegistrationState} from './certificate-state.js';
import {cloneJson} from './data-utils.js';
import {decodePayloadThroughApi} from './registration-result.js';
import {
    registrationDetailState,
    resetRegistrationDetailState,
} from './state.js';

export const EMPTY_DETAIL_PREPARATION = Object.freeze({
    attestationObjectValue: '',
    attestationDecodeError: '',
    authenticatorDataValue: '',
    authenticatorDecodeError: '',
});

export async function computeAuthenticatorDataHash() {
    registrationDetailState.authenticatorDataHash = '';
    registrationDetailState.authenticatorDataHex = '';

    const data = registrationDetailState.authenticatorData;
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

    const recordHexCandidate = value => {
        if (registrationDetailState.authenticatorDataHex) {
            return;
        }
        if (typeof value !== 'string') {
            return;
        }
        const trimmed = value.trim();
        if (!trimmed) {
            return;
        }
        registrationDetailState.authenticatorDataHex = trimmed.toLowerCase();
    };

    for (const candidate of hexCandidates) {
        const normalized = candidate.replace(/[^0-9a-f]/gi, '').toLowerCase();
        if (!normalized || normalized.length % 2 !== 0) {
            continue;
        }
        const converted = hexToUint8Array(normalized);
        if (converted && converted.length) {
            recordHexCandidate(normalized);
            bytes = converted;
            break;
        }
    }

    if (!bytes) {
        for (const candidate of base64UrlCandidates) {
            const converted = base64UrlToUint8Array(candidate);
            if (converted && converted.length) {
                recordHexCandidate(bytesToHex(converted));
                bytes = converted;
                break;
            }
        }
    }

    if (!bytes) {
        for (const candidate of base64Candidates) {
            const converted = base64ToUint8Array(candidate);
            if (converted && converted.length) {
                recordHexCandidate(bytesToHex(converted));
                bytes = converted;
                break;
            }
        }
    }

    if (!bytes || !bytes.length) {
        return '';
    }

    if (!registrationDetailState.authenticatorDataHex) {
        registrationDetailState.authenticatorDataHex = bytesToHex(bytes);
    }

    if (!window.crypto || !window.crypto.subtle || typeof window.crypto.subtle.digest !== 'function') {
        return '';
    }

    try {
        const digestBuffer = await window.crypto.subtle.digest('SHA-256', bytes);
        const hashHex = bytesToHex(new Uint8Array(digestBuffer));
        registrationDetailState.authenticatorDataHash = hashHex;
        return hashHex;
    } catch (error) {
        registrationDetailState.authenticatorDataHash = '';
        return '';
    }
}

export async function prepareRegistrationDetailState(options = {}) {
    const {
        attestationObjectValue = '',
        attestationObjectDecoded = null,
        authenticatorDataValue = '',
        fallbackCertificates = [],
        relyingPartyInfo = null,
        preferFallbackCertificates = false,
    } = options || {};

    resetRegistrationDetailState();

    const attestationValue = typeof attestationObjectValue === 'string'
        ? attestationObjectValue.trim()
        : '';
    const authenticatorValue = typeof authenticatorDataValue === 'string'
        ? authenticatorDataValue.trim()
        : '';

    let attestationDecodeError = '';
    let authenticatorDecodeError = '';

    if (fallbackCertificates) {
        addCertificatesToRegistrationState(fallbackCertificates);
    }

    const fallbackCertificatesAvailable = preferFallbackCertificates
        && registrationDetailState.attestationCertificates.length > 0;

    if (attestationValue) {
        try {
            const decoded = await decodePayloadThroughApi(attestationValue);
            const attestationData = decoded?.data?.attestationObject || decoded?.data || null;
            if (attestationData && typeof attestationData === 'object') {
                registrationDetailState.attestationObject = attestationData;
                if (
                    attestationData.attStmt
                    && typeof attestationData.attStmt === 'object'
                    && !fallbackCertificatesAvailable
                ) {
                    addCertificatesToRegistrationState(attestationData.attStmt.x5c);
                }
            }
            if (decoded?.data?.authenticatorData) {
                registrationDetailState.authenticatorData = decoded.data.authenticatorData;
            }
        } catch (error) {
            attestationDecodeError = error?.message || 'Failed to decode attestationObject.';
        }
    }

    const decodedObject = attestationObjectDecoded && typeof attestationObjectDecoded === 'object'
        ? attestationObjectDecoded
        : null;
    if (!registrationDetailState.attestationObject && decodedObject) {
        registrationDetailState.attestationObject = decodedObject;
        const attStmt = decodedObject.attStmt || decodedObject.att_statement || null;
        if (
            attStmt
            && typeof attStmt === 'object'
            && !fallbackCertificatesAvailable
        ) {
            addCertificatesToRegistrationState(attStmt.x5c || attStmt.X5C || []);
        }
    }

    if (!registrationDetailState.attestationCertificates.length && relyingPartyInfo?.attestationCertificate) {
        addCertificatesToRegistrationState(relyingPartyInfo.attestationCertificate);
    }
    if (!registrationDetailState.attestationCertificates.length && Array.isArray(relyingPartyInfo?.attestationCertificates)) {
        addCertificatesToRegistrationState(relyingPartyInfo.attestationCertificates);
    }

    if (!registrationDetailState.authenticatorData && authenticatorValue) {
        try {
            const decodedAuth = await decodePayloadThroughApi(authenticatorValue);
            if (decodedAuth?.data) {
                registrationDetailState.authenticatorData = decodedAuth.data;
            }
        } catch (error) {
            authenticatorDecodeError = error?.message || 'Failed to decode authenticatorData.';
        }
    }

    if (!registrationDetailState.authenticatorData && authenticatorValue) {
        const fallback = { base64url: authenticatorValue };
        try {
            fallback.raw = base64UrlToHex(authenticatorValue);
        } catch (error) {
            fallback.raw = authenticatorValue;
        }
        registrationDetailState.authenticatorData = fallback;
    }

    await computeAuthenticatorDataHash();

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

export function captureRegistrationDetailState(detailPreparation = EMPTY_DETAIL_PREPARATION) {
    const certificatesClone = cloneJson(registrationDetailState.attestationCertificates) || [];
    const visibleIndices = Array.isArray(registrationDetailState.visibleAttestationCertificateIndices)
        ? [...registrationDetailState.visibleAttestationCertificateIndices]
        : [];

    return {
        detailPreparation: normaliseDetailPreparationSnapshot(detailPreparation),
        attestationObject: cloneJson(registrationDetailState.attestationObject),
        attestationCertificates: Array.isArray(certificatesClone) ? certificatesClone : [],
        visibleAttestationCertificateIndices: visibleIndices,
        authenticatorData: cloneJson(registrationDetailState.authenticatorData),
        authenticatorDataHex: typeof registrationDetailState.authenticatorDataHex === 'string'
            ? registrationDetailState.authenticatorDataHex
            : '',
        authenticatorDataHash: typeof registrationDetailState.authenticatorDataHash === 'string'
            ? registrationDetailState.authenticatorDataHash
            : '',
    };
}

export function applyRegistrationDetailSnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== 'object') {
        return;
    }

    const stateSource = snapshot.state && typeof snapshot.state === 'object'
        ? snapshot.state
        : snapshot;

    const attObj = cloneJson(stateSource.attestationObject);
    registrationDetailState.attestationObject = attObj && typeof attObj === 'object' ? attObj : null;

    const certificatesClone = cloneJson(stateSource.attestationCertificates);
    registrationDetailState.attestationCertificates = Array.isArray(certificatesClone)
        ? certificatesClone
        : [];

    const indices = Array.isArray(stateSource.visibleAttestationCertificateIndices)
        ? [...stateSource.visibleAttestationCertificateIndices]
        : [];
    registrationDetailState.visibleAttestationCertificateIndices = indices;

    const authDataClone = cloneJson(stateSource.authenticatorData);
    registrationDetailState.authenticatorData = authDataClone && typeof authDataClone === 'object'
        ? authDataClone
        : null;

    registrationDetailState.authenticatorDataHex = typeof stateSource.authenticatorDataHex === 'string'
        ? stateSource.authenticatorDataHex
        : '';
    registrationDetailState.authenticatorDataHash = typeof stateSource.authenticatorDataHash === 'string'
        ? stateSource.authenticatorDataHash
        : '';

    if (!registrationDetailState.visibleAttestationCertificateIndices.length && registrationDetailState.attestationCertificates.length) {
        registrationDetailState.visibleAttestationCertificateIndices = registrationDetailState.attestationCertificates.map((_, index) => index);
    }

    if (registrationDetailState.authenticatorData && typeof registrationDetailState.authenticatorData === 'object') {
        if (registrationDetailState.authenticatorDataHex && !registrationDetailState.authenticatorData.raw) {
            registrationDetailState.authenticatorData.raw = registrationDetailState.authenticatorDataHex;
        }
    }

    return stateSource.detailPreparation
        ? normaliseDetailPreparationSnapshot(stateSource.detailPreparation)
        : { ...EMPTY_DETAIL_PREPARATION };
}
