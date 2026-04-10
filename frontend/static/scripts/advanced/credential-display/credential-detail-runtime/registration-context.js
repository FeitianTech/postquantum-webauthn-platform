import {
    base64ToBase64Url,
} from '../../../shared/utils/binary.js';
import {
    deriveAaguidFromCredentialData,
    normaliseAaguidValue,
} from '../../credential-utils.js';
import {extractAaguidFromCertificateEntries} from '../certificate-core.js';
import {
    collectTruthyEntries,
    cloneJson,
    normalizeClientDataString,
} from '../data-utils.js';
import {
    pickFirstObject,
    pickFirstString,
} from './helpers.js';
import {
    attestationObjectDecodedCandidates,
    attestationObjectStringCandidates,
    authenticatorDataHexCandidates,
    authenticatorDataStringCandidates,
    resolveStoredRegistrationResponse,
} from './registration-candidates.js';

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
        cred.attestationCertificate,
        cred.attestationCertificates,
        cred.attestation_certificate,
        cred.attestation_certificates,
        cred.properties?.attestationCertificate,
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

    const certificateAaguidHex = normaliseAaguidValue(
        extractAaguidFromCertificateEntries(fallbackCertificates)
    );
    const authDataAaguidHex = normaliseAaguidValue(deriveAaguidFromCredentialData(cred));

    const relyingPartyInfo = pickFirstObject(
        cred.relyingParty,
        cred.registrationRelyingParty,
        cred.registration_relying_party,
        cred.properties?.relyingParty,
    );

    const fallbackClientDataString = pickFirstString(
        cred.clientDataJSON,
        cred.clientDataJson,
        cred.clientData,
        typeof cred.client_data_json === 'string' ? cred.client_data_json : '',
    );

    const fallbackClientDataObject = pickFirstObject(
        typeof cred.client_data_json === 'object' ? cred.client_data_json : null,
        cred.clientDataParsed,
        cred.clientDataObject,
    );

    const registrationResponseStored = pickFirstObject(
        cred.registrationResponse,
        cred.registration_response,
        cred.registrationResult,
        cred.registration_result,
    );

    let registrationCredential = cloneJson(registrationResponseStored);
    if (!registrationCredential || typeof registrationCredential !== 'object') {
        registrationCredential = {};
    }

    if (!registrationCredential.response || typeof registrationCredential.response !== 'object') {
        registrationCredential.response = {};
    }

    const registrationResponse = registrationCredential.response;

    const credentialIdBase64 = pickFirstString(
        cred.credentialId,
        cred.credential_id,
        cred.credentialIdBase64,
    );

    let credentialIdBase64Url = '';
    if (credentialIdBase64) {
        try {
            credentialIdBase64Url = base64ToBase64Url(credentialIdBase64);
        } catch {
            credentialIdBase64Url = credentialIdBase64;
        }
    }

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
        cred.client_extension_outputs,
    );
    if (extensionResults && typeof extensionResults === 'object') {
        registrationCredential.clientExtensionResults = cloneJson(extensionResults) || extensionResults;
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
        fallbackClientDataObject,
        registrationCredential,
        authenticatorDataForDetail,
    };
}
