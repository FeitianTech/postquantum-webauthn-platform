import {
    MAX_AUTH_DATA_HASH_LENGTH,
    MAX_AUTH_DATA_HEX_LENGTH,
    MAX_DETAIL_STRING_LENGTH,
    MAX_SNAPSHOT_HTML_LENGTH,
    SNAPSHOT_ATTESTATION_STRIP_KEYS,
    SNAPSHOT_AUTH_DATA_STRIP_KEYS,
    SNAPSHOT_CERT_STRIP_KEYS,
    SNAPSHOT_EXTENSION_STRIP_KEYS,
} from './constants.js';
import { cloneJsonValue, truncateString } from './common.js';

export function stripKeysRecursively(target, keys, skipRoot = false) {
    if (!target || typeof target !== 'object' || !Array.isArray(keys) || !keys.length) {
        return;
    }

    if (Array.isArray(target)) {
        target.forEach(item => {
            if (item && typeof item === 'object') {
                stripKeysRecursively(item, keys, false);
            }
        });
        return;
    }

    if (!skipRoot) {
        keys.forEach(key => {
            if (Object.prototype.hasOwnProperty.call(target, key)) {
                delete target[key];
            }
        });
    }

    Object.keys(target).forEach(key => {
        const value = target[key];
        if (value && typeof value === 'object') {
            stripKeysRecursively(value, keys, false);
        }
    });
}

function sanitiseParsedCertificateForSnapshot(parsed) {
    const parsedClone = cloneJsonValue(parsed);
    if (!parsedClone) {
        return null;
    }

    stripKeysRecursively(parsedClone, SNAPSHOT_CERT_STRIP_KEYS, false);

    if (Array.isArray(parsedClone.extensions)) {
        parsedClone.extensions = parsedClone.extensions
            .map(ext => {
                const extClone = cloneJsonValue(ext);
                if (!extClone) {
                    return null;
                }
                stripKeysRecursively(extClone, SNAPSHOT_EXTENSION_STRIP_KEYS, false);
                return extClone;
            })
            .filter(Boolean);
    }

    return parsedClone;
}

function sanitiseCertificateEntryForSnapshot(entry) {
    const clone = cloneJsonValue(entry);
    if (!clone) {
        return null;
    }

    stripKeysRecursively(clone, SNAPSHOT_CERT_STRIP_KEYS, false);

    if (clone.parsedX5c && typeof clone.parsedX5c === 'object') {
        const sanitisedParsed = sanitiseParsedCertificateForSnapshot(clone.parsedX5c);
        if (sanitisedParsed) {
            clone.parsedX5c = sanitisedParsed;
        } else {
            delete clone.parsedX5c;
        }
    } else if (clone.parsed && typeof clone.parsed === 'object') {
        const sanitisedParsed = sanitiseParsedCertificateForSnapshot(clone.parsed);
        if (sanitisedParsed) {
            clone.parsedX5c = sanitisedParsed;
        }
        delete clone.parsed;
    }

    return Object.keys(clone).length ? clone : null;
}

function sanitiseDetailPreparationSnapshot(preparation) {
    if (!preparation || typeof preparation !== 'object') {
        return null;
    }

    return {
        attestationObjectValue: truncateString(preparation.attestationObjectValue || '', MAX_DETAIL_STRING_LENGTH),
        attestationDecodeError: truncateString(preparation.attestationDecodeError || '', MAX_DETAIL_STRING_LENGTH),
        authenticatorDataValue: truncateString(preparation.authenticatorDataValue || '', MAX_DETAIL_STRING_LENGTH),
        authenticatorDecodeError: truncateString(preparation.authenticatorDecodeError || '', MAX_DETAIL_STRING_LENGTH),
    };
}

function sanitiseAttestationObjectForSnapshot(attestationObject) {
    const clone = cloneJsonValue(attestationObject);
    if (!clone) {
        return null;
    }

    if (clone.attStmt && typeof clone.attStmt === 'object') {
        const attStmtClone = { ...clone.attStmt };
        if (Array.isArray(attStmtClone.x5c)) {
            attStmtClone.x5c = new Array(attStmtClone.x5c.length).fill(null);
        }
        stripKeysRecursively(attStmtClone, SNAPSHOT_ATTESTATION_STRIP_KEYS, false);
        clone.attStmt = attStmtClone;
    }

    return clone;
}

function sanitiseAuthenticatorDataForSnapshot(authData) {
    const clone = cloneJsonValue(authData);
    if (!clone) {
        return null;
    }

    stripKeysRecursively(clone, SNAPSHOT_AUTH_DATA_STRIP_KEYS, false);
    return clone;
}

function sanitiseRegistrationDetailStateSnapshot(state) {
    if (!state || typeof state !== 'object') {
        return null;
    }

    const sanitised = {};

    if (state.detailPreparation && typeof state.detailPreparation === 'object') {
        const detailClone = sanitiseDetailPreparationSnapshot(state.detailPreparation);
        if (detailClone) {
            sanitised.detailPreparation = detailClone;
        }
    }

    if (state.attestationObject && typeof state.attestationObject === 'object') {
        const attestationClone = sanitiseAttestationObjectForSnapshot(state.attestationObject);
        if (attestationClone) {
            sanitised.attestationObject = attestationClone;
        }
    }

    if (Array.isArray(state.attestationCertificates)) {
        const certificates = state.attestationCertificates
            .map(sanitiseCertificateEntryForSnapshot)
            .filter(Boolean);
        if (certificates.length) {
            sanitised.attestationCertificates = certificates;
        }
    }

    if (Array.isArray(state.visibleAttestationCertificateIndices)) {
        const indices = state.visibleAttestationCertificateIndices
            .map(index => Number.parseInt(index, 10))
            .filter(Number.isFinite);
        if (indices.length) {
            sanitised.visibleAttestationCertificateIndices = indices;
        }
    }

    if (state.authenticatorData && typeof state.authenticatorData === 'object') {
        const authClone = sanitiseAuthenticatorDataForSnapshot(state.authenticatorData);
        if (authClone) {
            sanitised.authenticatorData = authClone;
        }
    }

    if (typeof state.authenticatorDataHex === 'string' && state.authenticatorDataHex.trim()) {
        sanitised.authenticatorDataHex = truncateString(state.authenticatorDataHex.trim(), MAX_AUTH_DATA_HEX_LENGTH);
    }

    if (typeof state.authenticatorDataHash === 'string' && state.authenticatorDataHash.trim()) {
        sanitised.authenticatorDataHash = truncateString(state.authenticatorDataHash.trim(), MAX_AUTH_DATA_HASH_LENGTH);
    }

    return Object.keys(sanitised).length ? sanitised : null;
}

export function sanitiseRegistrationDetailSnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== 'object') {
        return null;
    }

    const sanitised = {};

    if (typeof snapshot.schemaVersion === 'number') {
        sanitised.schemaVersion = snapshot.schemaVersion;
    }

    if (typeof snapshot.capturedAt === 'string' && snapshot.capturedAt.trim()) {
        sanitised.capturedAt = snapshot.capturedAt.trim();
    }

    if (typeof snapshot.html === 'string' && snapshot.html.trim()) {
        sanitised.html = truncateString(snapshot.html.trim(), MAX_SNAPSHOT_HTML_LENGTH);
    }

    if (typeof snapshot.attestationSectionHtml === 'string' && snapshot.attestationSectionHtml.trim()) {
        sanitised.attestationSectionHtml = truncateString(snapshot.attestationSectionHtml.trim(), MAX_SNAPSHOT_HTML_LENGTH);
    }

    if (!sanitised.html && typeof snapshot.combinedHtml === 'string' && snapshot.combinedHtml.trim()) {
        sanitised.html = truncateString(snapshot.combinedHtml.trim(), MAX_SNAPSHOT_HTML_LENGTH);
    } else if (typeof snapshot.combinedHtml === 'string' && snapshot.combinedHtml.trim()) {
        sanitised.combinedHtml = truncateString(snapshot.combinedHtml.trim(), MAX_SNAPSHOT_HTML_LENGTH);
    }

    const stateClone = sanitiseRegistrationDetailStateSnapshot(snapshot.state || snapshot.stateSnapshot || {});
    if (stateClone) {
        sanitised.state = stateClone;
    }

    return Object.keys(sanitised).length ? sanitised : null;
}
