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

export function buildRegistrationContext(cred, {
    snapshotState = null,
    detailPreparation = null,
} = {}) {
    let attestationObjectValue = pickFirstString(
        ...attestationObjectStringCandidates(cred),
    );

    let attestationObjectDecoded = pickFirstObject(
        ...attestationObjectDecodedCandidates(cred),
    );

    let authenticatorDataBase64 = pickFirstString(
        ...authenticatorDataStringCandidates(cred),
    );

    let authenticatorDataHex = pickFirstString(
        ...authenticatorDataHexCandidates(cred),
    );

    let fallbackCertificates = collectTruthyEntries(
        cred.properties?.attestationCertificates,
        cred.relyingParty?.attestationCertificate,
        cred.relyingParty?.attestationCertificates,
    );

    if (snapshotState) {
        const attObjSnapshot = cloneJson(snapshotState.attestationObject);
        if (attObjSnapshot && typeof attObjSnapshot === 'object') {
            attestationObjectDecoded = attObjSnapshot;
        }

        const certSnapshot = cloneJson(snapshotState.attestationCertificates);
        if (Array.isArray(certSnapshot)) {
            fallbackCertificates = certSnapshot;
        }

        if (typeof snapshotState.authenticatorDataHex === 'string') {
            authenticatorDataHex = snapshotState.authenticatorDataHex;
        }
    }

    if (detailPreparation) {
        attestationObjectValue = detailPreparation.attestationObjectValue || attestationObjectValue;
        authenticatorDataBase64 = detailPreparation.authenticatorDataValue || authenticatorDataBase64;
    }

    const certificateAaguidHex = aaguidHex(
        extractAaguidFromCertificateEntries(fallbackCertificates)
    );
    const authDataAaguidHex = aaguidHex(deriveAaguidFromCredentialData(cred));

    const relyingPartyInfo = pickFirstObject(cred.relyingParty);

    const fallbackClientDataString = pickFirstString(cred.clientDataJSON);

    const registrationResponseStored = pickFirstObject(cred.registrationResponse);

    let registrationCredential = cloneJson(registrationResponseStored);
    if (!registrationCredential || typeof registrationCredential !== 'object') {
        registrationCredential = {};
    }

    if (!registrationCredential.response || typeof registrationCredential.response !== 'object') {
        registrationCredential.response = {};
    }

    const registrationResponse = registrationCredential.response;

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

    const storedRegistrationResponse = resolveStoredRegistrationResponse(registrationResponseStored);

    if (!attestationObjectValue) {
        attestationObjectValue = pickFirstString(
            ...attestationObjectStringCandidates(storedRegistrationResponse),
            ...attestationObjectStringCandidates(registrationCredential),
        );
    }

    if (!attestationObjectDecoded) {
        attestationObjectDecoded = pickFirstObject(
            ...attestationObjectDecodedCandidates(storedRegistrationResponse),
            ...attestationObjectDecodedCandidates(registrationCredential),
        );
    }

    if (!authenticatorDataBase64) {
        authenticatorDataBase64 = pickFirstString(
            ...authenticatorDataStringCandidates(storedRegistrationResponse),
            ...authenticatorDataStringCandidates(registrationCredential),
        );
    }

    if (!authenticatorDataHex) {
        authenticatorDataHex = pickFirstString(
            ...authenticatorDataHexCandidates(storedRegistrationResponse),
            ...authenticatorDataHexCandidates(registrationCredential),
        );
    }

    if (attestationObjectValue && !registrationResponse.attestationObject) {
        registrationResponse.attestationObject = attestationObjectValue;
    }

    if (attestationObjectDecoded && !registrationResponse.attestationObjectDecoded) {
        registrationResponse.attestationObjectDecoded = attestationObjectDecoded;
    }

    const normalizedClientDataForResponse = normalizeClientDataString(
        registrationResponse.clientDataJSON || fallbackClientDataString,
    );
    if (normalizedClientDataForResponse && !registrationResponse.clientDataJSON) {
        registrationResponse.clientDataJSON = normalizedClientDataForResponse;
    }

    if (authenticatorDataBase64 && !registrationResponse.authenticatorData) {
        registrationResponse.authenticatorData = authenticatorDataBase64;
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

    const authenticatorDataForDetail = authenticatorDataBase64 || authenticatorDataHex || '';

    return {
        attestationObjectValue,
        attestationObjectDecoded,
        authenticatorDataHex,
        fallbackCertificates,
        certificateAaguidHex,
        authDataAaguidHex,
        relyingPartyInfo,
        fallbackClientDataString,
        registrationCredential,
        authenticatorDataForDetail,
    };
}
