import {
    MAX_AUTH_DATA_HASH_LENGTH,
    MAX_AUTH_DATA_HEX_LENGTH,
    MAX_DETAIL_STRING_LENGTH,
    MAX_SNAPSHOT_RESPONSE_LENGTH,
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
            if (Object.hasOwn(target, key)) {
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

// Called with an object (the entry's own check).
function sanitiseParsedCertificateForSnapshot(parsed) {
    const parsedClone = cloneJsonValue(parsed);

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
        clone.parsedX5c = sanitiseParsedCertificateForSnapshot(clone.parsedX5c);
    } else if (clone.parsed && typeof clone.parsed === 'object') {
        clone.parsedX5c = sanitiseParsedCertificateForSnapshot(clone.parsed);
        delete clone.parsed;
    }

    return Object.keys(clone).length ? clone : null;
}

// Called with an object (sanitiseRegistrationDetailStateSnapshot checks).
function sanitiseDetailPreparationSnapshot(preparation) {
    return {
        attestationObjectValue: truncateString(preparation.attestationObjectValue || '', MAX_DETAIL_STRING_LENGTH),
        attestationDecodeError: truncateString(preparation.attestationDecodeError || '', MAX_DETAIL_STRING_LENGTH),
        authenticatorDataValue: truncateString(preparation.authenticatorDataValue || '', MAX_DETAIL_STRING_LENGTH),
        authenticatorDecodeError: truncateString(preparation.authenticatorDecodeError || '', MAX_DETAIL_STRING_LENGTH),
    };
}

// Called with an object (sanitiseRegistrationDetailStateSnapshot checks).
function sanitiseAttestationObjectForSnapshot(attestationObject) {
    const clone = cloneJsonValue(attestationObject);

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

// Called with an object (sanitiseRegistrationDetailStateSnapshot checks).
function sanitiseAuthenticatorDataForSnapshot(authData) {
    const clone = cloneJsonValue(authData);

    stripKeysRecursively(clone, SNAPSHOT_AUTH_DATA_STRIP_KEYS, false);
    return clone;
}

function sanitiseRegistrationDetailStateSnapshot(state) {
    if (!state || typeof state !== 'object') {
        return null;
    }

    const sanitised = {};

    if (state.detailPreparation && typeof state.detailPreparation === 'object') {
        sanitised.detailPreparation = sanitiseDetailPreparationSnapshot(state.detailPreparation);
    }

    if (state.attestationObject && typeof state.attestationObject === 'object') {
        sanitised.attestationObject = sanitiseAttestationObjectForSnapshot(state.attestationObject);
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
        sanitised.authenticatorData = sanitiseAuthenticatorDataForSnapshot(state.authenticatorData);
    }

    if (typeof state.authenticatorDataHex === 'string' && state.authenticatorDataHex.trim()) {
        sanitised.authenticatorDataHex = truncateString(state.authenticatorDataHex.trim(), MAX_AUTH_DATA_HEX_LENGTH);
    }

    if (typeof state.authenticatorDataHash === 'string' && state.authenticatorDataHash.trim()) {
        sanitised.authenticatorDataHash = truncateString(state.authenticatorDataHash.trim(), MAX_AUTH_DATA_HASH_LENGTH);
    }

    return Object.keys(sanitised).length ? sanitised : null;
}

function fitsInSnapshot(value) {
    try {
        return JSON.stringify(value).length <= MAX_SNAPSHOT_RESPONSE_LENGTH;
    } catch (error) {
        return false;
    }
}

// The registration as data: the response the browser returned and the relying
// party's view of it. Each is kept whole or not at all.
function sanitiseSnapshotResponse(response) {
    if (!response || typeof response !== 'object') {
        return null;
    }

    const sanitised = {};
    ['credential', 'relyingParty'].forEach(key => {
        const clone = cloneJsonValue(response[key]);
        if (clone && typeof clone === 'object' && !Array.isArray(clone) && fitsInSnapshot(clone)) {
            sanitised[key] = clone;
        }
    });

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

    const stateClone = sanitiseRegistrationDetailStateSnapshot(snapshot.state || {});
    if (stateClone) {
        sanitised.state = stateClone;
    }

    const responseClone = sanitiseSnapshotResponse(snapshot.response);
    if (responseClone) {
        sanitised.response = responseClone;
    }

    // Composed HTML, which older snapshots carried, is not kept: the view is built
    // from the state and the response. A snapshot with neither holds nothing.
    return sanitised.state || sanitised.response ? sanitised : null;
}
