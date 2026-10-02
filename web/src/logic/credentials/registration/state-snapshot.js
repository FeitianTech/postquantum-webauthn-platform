// A registration state as a saved snapshot keeps it (`schemaVersion` 2's
// `state`), and a state filled from one, as it was captured. DOM-free.
import {cloneJson} from '../../shared/json.js';
import {EMPTY_DETAIL_PREPARATION} from './state.js';

/** @import { DetailPreparation, RegistrationState } from './state.js' */

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
