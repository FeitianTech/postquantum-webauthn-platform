import {
    base64ToBase64Url,
} from '../../shared/bytes.js';
import { deriveAaguidFromCredentialData } from '../record-fields.js';
import { aaguidHex } from '../../shared/aaguid.js';
import {extractAaguidFromCertificateEntries} from '../certificates/core.js';
import { cloneJson } from '../../shared/json.js';
import {
    collectTruthyEntries,
    normalizeClientDataString,
} from '../registration/data-utils.js';
import {
    attestationObjectDecodedCandidates,
    attestationObjectStringCandidates,
    authenticatorDataHexCandidates,
    authenticatorDataStringCandidates,
    pickFirstObject,
    pickFirstString,
    resolveStoredRegistrationResponse,
} from './registration-fields.js';

/** @import { DetailPreparation } from '../registration/state.js' */

/**
 * The registration's values as the record keeps them, then as its saved
 * snapshot and what it said about the decodes have them.
 * @param {Record<string, any>} cred
 * @param {Record<string, any> | null} snapshotState
 * @param {DetailPreparation | null} detailPreparation
 */
function storedRegistrationValues(cred, snapshotState, detailPreparation) {
    const values = {
        attestationObjectValue: pickFirstString(...attestationObjectStringCandidates(cred)),
        attestationObjectDecoded: pickFirstObject(...attestationObjectDecodedCandidates(cred)),
        authenticatorDataBase64: pickFirstString(...authenticatorDataStringCandidates(cred)),
        authenticatorDataHex: pickFirstString(...authenticatorDataHexCandidates(cred)),
        fallbackCertificates: collectTruthyEntries(
            cred.properties?.attestationCertificates,
            cred.relyingParty?.attestationCertificate,
            cred.relyingParty?.attestationCertificates,
        ),
    };

    if (snapshotState) {
        const attObjSnapshot = cloneJson(snapshotState.attestationObject);
        if (attObjSnapshot && typeof attObjSnapshot === 'object') {
            values.attestationObjectDecoded = attObjSnapshot;
        }

        const certSnapshot = cloneJson(snapshotState.attestationCertificates);
        if (Array.isArray(certSnapshot)) {
            values.fallbackCertificates = certSnapshot;
        }

        if (typeof snapshotState.authenticatorDataHex === 'string') {
            values.authenticatorDataHex = snapshotState.authenticatorDataHex;
        }
    }

    if (detailPreparation) {
        values.attestationObjectValue = detailPreparation.attestationObjectValue || values.attestationObjectValue;
        values.authenticatorDataBase64 = detailPreparation.authenticatorDataValue || values.authenticatorDataBase64;
    }
    return values;
}

/** @typedef {ReturnType<typeof storedRegistrationValues>} RegistrationValues */

/**
 * The browser's credential as the record keeps it, a copy: with the record's
 * credential ID as its ID when it has none, a type, and a response to fill.
 * @param {Record<string, any>} cred
 * @returns {Record<string, any>}
 */
function storedRegistrationCredential(cred, registrationResponseStored) {
    let registrationCredential = cloneJson(registrationResponseStored);
    if (!registrationCredential || typeof registrationCredential !== 'object') {
        registrationCredential = {};
    }

    if (!registrationCredential.response || typeof registrationCredential.response !== 'object') {
        registrationCredential.response = {};
    }

    const credentialIdBase64 = pickFirstString(cred.credentialId);

    const credentialIdBase64Url = credentialIdBase64 ? base64ToBase64Url(credentialIdBase64) : '';

    if (credentialIdBase64Url) {
        if (!registrationCredential.id) {
            registrationCredential.id = credentialIdBase64Url;
        }
        if (!registrationCredential.rawId) {
            registrationCredential.rawId = credentialIdBase64Url;
        }
    }

    if (!registrationCredential.type) {
        registrationCredential.type = 'public-key';
    }
    return registrationCredential;
}

/**
 * What the record's values lack, from the response it kept, then from the credential's.
 * @param {RegistrationValues} values
 * @param {Record<string, any>} registrationCredential
 */
function valuesFromResponses(values, storedRegistrationResponse, registrationCredential) {
    if (!values.attestationObjectValue) {
        values.attestationObjectValue = pickFirstString(
            ...attestationObjectStringCandidates(storedRegistrationResponse),
            ...attestationObjectStringCandidates(registrationCredential),
        );
    }

    if (!values.attestationObjectDecoded) {
        values.attestationObjectDecoded = pickFirstObject(
            ...attestationObjectDecodedCandidates(storedRegistrationResponse),
            ...attestationObjectDecodedCandidates(registrationCredential),
        );
    }

    if (!values.authenticatorDataBase64) {
        values.authenticatorDataBase64 = pickFirstString(
            ...authenticatorDataStringCandidates(storedRegistrationResponse),
            ...authenticatorDataStringCandidates(registrationCredential),
        );
    }

    if (!values.authenticatorDataHex) {
        values.authenticatorDataHex = pickFirstString(
            ...authenticatorDataHexCandidates(storedRegistrationResponse),
            ...authenticatorDataHexCandidates(registrationCredential),
        );
    }
}

/**
 * The credential's response given what it lacks of the values (the decoded
 * attestation object too, which the details show when a snapshot has a state
 * but no response), and the credential its extension outputs and attachment.
 * @param {Record<string, any>} registrationCredential
 * @param {RegistrationValues} values
 * @param {string} fallbackClientDataString
 * @param {Record<string, any>} cred
 */
function fillRegistrationResponse(registrationCredential, values, fallbackClientDataString, cred) {
    const registrationResponse = registrationCredential.response;

    if (values.attestationObjectValue && !registrationResponse.attestationObject) {
        registrationResponse.attestationObject = values.attestationObjectValue;
    }

    if (values.attestationObjectDecoded && !registrationResponse.attestationObjectDecoded) {
        registrationResponse.attestationObjectDecoded = values.attestationObjectDecoded;
    }

    const normalizedClientDataForResponse = normalizeClientDataString(
        registrationResponse.clientDataJSON || fallbackClientDataString,
    );
    if (normalizedClientDataForResponse && !registrationResponse.clientDataJSON) {
        registrationResponse.clientDataJSON = normalizedClientDataForResponse;
    }

    if (values.authenticatorDataBase64 && !registrationResponse.authenticatorData) {
        registrationResponse.authenticatorData = values.authenticatorDataBase64;
    }

    const extensionResults = pickFirstObject(
        registrationCredential.clientExtensionResults,
        cred.clientExtensionOutputs,
    );
    if (extensionResults && typeof extensionResults === 'object') {
        registrationCredential.clientExtensionResults = cloneJson(extensionResults);
    }

    if (cred.authenticatorAttachment && !registrationCredential.authenticatorAttachment) {
        registrationCredential.authenticatorAttachment = cred.authenticatorAttachment;
    }
}

/**
 * @param {Record<string, any>} cred
 * @param {{ snapshotState?: Record<string, any> | null, detailPreparation?: DetailPreparation | null }} [snapshot]
 */
export function buildRegistrationContext(cred, {
    snapshotState = null,
    detailPreparation = null,
} = {}) {
    const values = storedRegistrationValues(cred, snapshotState, detailPreparation);

    const certificateAaguidHex = aaguidHex(
        extractAaguidFromCertificateEntries(values.fallbackCertificates)
    );
    const authDataAaguidHex = aaguidHex(deriveAaguidFromCredentialData(cred));

    const relyingPartyInfo = pickFirstObject(cred.relyingParty);

    const fallbackClientDataString = pickFirstString(cred.clientDataJSON);

    const registrationResponseStored = pickFirstObject(cred.registrationResponse);
    const registrationCredential = storedRegistrationCredential(cred, registrationResponseStored);

    valuesFromResponses(values, resolveStoredRegistrationResponse(registrationResponseStored), registrationCredential);
    fillRegistrationResponse(registrationCredential, values, fallbackClientDataString, cred);

    return {
        attestationObjectValue: values.attestationObjectValue,
        attestationObjectDecoded: values.attestationObjectDecoded,
        authenticatorDataHex: values.authenticatorDataHex,
        fallbackCertificates: values.fallbackCertificates,
        certificateAaguidHex,
        authDataAaguidHex,
        relyingPartyInfo,
        fallbackClientDataString,
        registrationCredential,
        authenticatorDataForDetail: values.authenticatorDataBase64 || values.authenticatorDataHex || '',
    };
}
