// What the registration view shows, as data: the browser's response and its
// client data, the relying party's view of the registration, the attestation
// object with its certificates and authenticator data, and each certificate's
// and the authenticator data's own view. DOM-free. The state the view is built
// from is passed in (./registration-state.js).
import {
    base64UrlToJson,
    base64UrlToUtf8String,
} from '../../shared/utils/binary.js';
import {
    normaliseCertificateEntryForModal,
    partitionCertificateEntries,
} from './certificate-core.js';
import {formatCertificateDetails} from './certificate-text.js';
import {
    collectTruthyEntries,
    normalizeClientDataString,
} from './data-utils.js';
import {
    applyRegistrationSnapshot,
    captureRegistrationState,
    hashAuthenticatorData,
    prepareRegistrationState,
    visibleStateCertificates,
} from './registration-state.js';
import {sanitiseAttestationObjectForDisplay} from './sanitize-attestation-object.js';
import {sanitizeRelyingPartyInfo} from './sanitize-common.js';

export const REGISTRATION_TEXT = Object.freeze({
    responseTitle: 'Authenticator Response',
    createResponse: 'Response for navigator.credentials.create()',
    noCredentialResponse: 'No credential response captured.',
    parsedClientData: 'Parsed clientDataJSON',
    noClientData: 'No clientDataJSON available.',
    serverDataTitle: 'Server-retrieved Data',
    noRelyingParty: 'No relying party data returned.',
    attestationTitle: 'Attestation Information',
    attestationObject: 'Attestation Object',
    unprepared: 'Unable to prepare decoded attestationObject.',
    undecodable: 'Unable to decode attestationObject.',
    noAttestationObject: 'No attestationObject was provided.',
    certificate: 'Attestation Certificate',
    noCertificates: 'No attestation certificates available.',
    authenticatorData: 'Authenticator Data',
    noCertificateDetails: 'No decoded certificate details available.',
});

/** A certificate's title: "Attestation Certificate", numbered from 1 when there are several. */
export function certificateTitle(displayIndex, count) {
    return count === 1
        ? REGISTRATION_TEXT.certificate
        : `${REGISTRATION_TEXT.certificate} ${displayIndex + 1}`;
}

/** The decoded attestation object as the view shows it, as JSON; '' when it cannot be written. */
export function attestationObjectJson(attestationObject, attestationFormatRaw, certificates) {
    const attestationDisplay = sanitiseAttestationObjectForDisplay(
        attestationObject,
        attestationFormatRaw,
        certificates,
    ) || attestationObject;
    try {
        return JSON.stringify(attestationDisplay, null, 2);
    } catch (error) {
        try {
            return JSON.stringify(attestationObject, null, 2);
        } catch (jsonError) {
            return '';
        }
    }
}

/**
 * "Attestation Information", or null when the registration has no attestation:
 * the attestation object's body (its JSON, or why there is none), a button per
 * certificate that parsed, "Authenticator Data" when there is some, and the
 * messages. Records in `state` which certificates the view lists.
 */
export function describeAttestationSection(state, {
    attestationObjectValue = '',
    attestationDecodeError = '',
    attestationFormatRaw = '',
    attestationStatement = null,
    authenticatorDataValue = '',
    authenticatorDecodeError = '',
} = {}) {
    const attestationObject = state.attestationObject;
    const attestationStatementObject = attestationStatement && typeof attestationStatement === 'object'
        ? attestationStatement
        : attestationObject && typeof attestationObject.attStmt === 'object'
            ? attestationObject.attStmt
            : null;
    const attestationStatementHasContent = attestationStatementObject && Object.keys(attestationStatementObject).length > 0;

    const certificatesAll = Array.isArray(state.attestationCertificates)
        ? state.attestationCertificates
        : [];
    const { valid: certificateInfos } = partitionCertificateEntries(certificatesAll);
    const attestationHasCertificates = certificateInfos.length > 0;

    state.visibleAttestationCertificateIndices = certificateInfos.map(info => info.index);

    const hasAttestationObject = Boolean(
        attestationObject
        && typeof attestationObject === 'object'
        && Object.keys(attestationObject).length > 0,
    );
    const hasAttestationValue = typeof attestationObjectValue === 'string'
        ? attestationObjectValue.trim() !== ''
        : false;

    const hasAttestation = hasAttestationObject
        || hasAttestationValue
        || attestationStatementHasContent
        || attestationHasCertificates;

    if (!hasAttestation) {
        return null;
    }

    const hasAuthenticatorData = Boolean(state.authenticatorData);

    let body;
    if (attestationObject) {
        const text = attestationObjectJson(attestationObject, attestationFormatRaw, certificatesAll);
        body = text
            ? { kind: 'json', text }
            : { kind: 'placeholder', text: REGISTRATION_TEXT.unprepared };
    } else if (attestationObjectValue) {
        body = { kind: 'error', text: attestationDecodeError || REGISTRATION_TEXT.undecodable };
    } else {
        body = { kind: 'placeholder', text: REGISTRATION_TEXT.noAttestationObject };
    }

    const certificates = certificateInfos.map((info, displayIndex) => ({
        index: displayIndex,
        title: certificateTitle(displayIndex, certificateInfos.length),
    }));
    const certificateMessage = !attestationHasCertificates
        && (hasAttestationObject || hasAttestationValue || attestationStatementHasContent)
        ? REGISTRATION_TEXT.noCertificates
        : '';

    return {
        body,
        certificates,
        certificateMessage,
        hasAuthenticatorData,
        authenticatorError: !hasAuthenticatorData && authenticatorDataValue && authenticatorDecodeError
            ? authenticatorDecodeError
            : '',
    };
}

/** The parsed client data as the view shows it: indented JSON, else its text, else ''. */
export function describeClientData(credentialJson, fallbackClientData, fallbackParsedClientData) {
    const fallbackClientDataString = typeof fallbackClientData === 'string'
        ? fallbackClientData.trim()
        : '';
    const normalizedFallbackClientData = fallbackClientDataString
        ? normalizeClientDataString(fallbackClientDataString)
        : '';

    let clientDataBase64 = credentialJson?.response?.clientDataJSON;
    if (!clientDataBase64 && normalizedFallbackClientData) {
        clientDataBase64 = normalizedFallbackClientData;
    }

    let parsedClientData = null;
    if (clientDataBase64) {
        parsedClientData = base64UrlToJson(clientDataBase64);
    }

    if (!parsedClientData && fallbackParsedClientData && typeof fallbackParsedClientData === 'object') {
        parsedClientData = fallbackParsedClientData;
    }

    if (parsedClientData) {
        return JSON.stringify(parsedClientData, null, 2);
    }
    if (clientDataBase64) {
        // Text that is not base64url of anything is shown as it is stored.
        let text = null;
        try {
            text = base64UrlToUtf8String(clientDataBase64);
        } catch (error) {
            text = null;
        }
        return text || clientDataBase64;
    }
    return fallbackClientDataString;
}

/**
 * The registration's view as data, and what its snapshot keeps. A saved
 * snapshot's state is shown as it is; otherwise the attestation object and the
 * authenticator data are decoded through `decode` into `state`.
 */
export async function composeRegistration({
    credentialJson = null,
    relyingPartyInfo = null,
    attestationObjectValue = '',
    attestationObjectDecoded = null,
    authenticatorDataValue = '',
    authenticatorDataHex = '',
    fallbackCertificates = [],
    fallbackClientData = null,
    fallbackParsedClientData = null,
    preferFallbackCertificates = false,
    snapshotState = null,
} = {}, { state, decode }) {
    const clientDataDisplay = describeClientData(credentialJson, fallbackClientData, fallbackParsedClientData);

    // A saved snapshot already holds the decoded attestation and certificates:
    // show those as they are, without asking the server to decode again.
    const detailPreparation = snapshotState && typeof snapshotState === 'object'
        ? applyRegistrationSnapshot(state, snapshotState)
        : await prepareRegistrationState(state, {
            attestationObjectValue,
            attestationObjectDecoded,
            authenticatorDataValue,
            fallbackCertificates,
            relyingPartyInfo,
            preferFallbackCertificates,
        }, { decode });

    const authDataState = state.authenticatorData;
    if (authDataState) {
        if (detailPreparation.authenticatorDataValue && typeof authDataState.base64url !== 'string') {
            authDataState.base64url = detailPreparation.authenticatorDataValue;
        }
        if (authenticatorDataHex && typeof authDataState.raw !== 'string') {
            authDataState.raw = authenticatorDataHex;
        }
    } else if (detailPreparation.authenticatorDataValue || authenticatorDataHex) {
        state.authenticatorData = {};
        if (detailPreparation.authenticatorDataValue) {
            state.authenticatorData.base64url = detailPreparation.authenticatorDataValue;
        }
        if (authenticatorDataHex) {
            state.authenticatorData.raw = authenticatorDataHex;
        }
    }

    // The decoder's authenticator data holds no bytes of its own, so the hash
    // (prepareRegistrationState) found none until the base64url was attached above.
    if (state.authenticatorData && !state.authenticatorDataHash) {
        await hashAuthenticatorData(state);
    }

    // Both are text: the snapshot's (applyRegistrationSnapshot) or the hash's.
    const authenticatorSummary = {
        authenticatorDataHex: state.authenticatorDataHex,
        authenticatorDataHash: state.authenticatorDataHash,
    };

    const relyingPartyCopy = sanitizeRelyingPartyInfo(relyingPartyInfo, authenticatorSummary);

    const attestationObject = state.attestationObject;
    const attestationFormatFromRp = typeof relyingPartyInfo?.attestationFmt === 'string'
        ? relyingPartyInfo.attestationFmt
        : '';
    const attestationFormatFromObject = attestationObject && typeof attestationObject.fmt === 'string'
        ? attestationObject.fmt
        : attestationObjectDecoded && typeof attestationObjectDecoded === 'object' && typeof attestationObjectDecoded.fmt === 'string'
            ? attestationObjectDecoded.fmt
            : '';
    const attestationFormatRaw = attestationFormatFromRp || attestationFormatFromObject || '';
    const attestationStatement = attestationObject && typeof attestationObject.attStmt === 'object'
        ? attestationObject.attStmt
        : attestationObjectDecoded && typeof attestationObjectDecoded === 'object' && typeof attestationObjectDecoded.attStmt === 'object'
            ? attestationObjectDecoded.attStmt
            : null;

    const attestation = describeAttestationSection(state, {
        attestationObjectValue: detailPreparation.attestationObjectValue,
        attestationDecodeError: detailPreparation.attestationDecodeError,
        attestationFormatRaw,
        attestationStatement,
        authenticatorDataValue: detailPreparation.authenticatorDataValue,
        authenticatorDecodeError: detailPreparation.authenticatorDecodeError,
    });

    return {
        response: {
            credential: credentialJson && typeof credentialJson === 'object'
                ? JSON.stringify(credentialJson, null, 2)
                : '',
            clientData: clientDataDisplay,
            relyingParty: relyingPartyCopy ? JSON.stringify(relyingPartyCopy, null, 2) : '',
        },
        attestation,
        stateSnapshot: captureRegistrationState(state, detailPreparation),
        relyingPartyCopy,
    };
}

/**
 * A listed certificate's own view (numbered from 0 in the list's order): its
 * title, its text, the parser's error when there is no text, or neither; and its
 * decoded details. Null when the view lists no such certificate.
 */
export function describeAttestationCertificate(state, index) {
    const visibleCertificates = visibleStateCertificates(state);
    const normalised = normaliseCertificateEntryForModal(visibleCertificates[index]);
    if (!normalised) {
        return null;
    }

    // normaliseCertificateEntryForModal always gives parsedX5c an object.
    const parsed = normalised.parsedX5c;
    const error = typeof parsed.error === 'string' ? parsed.error.trim() : '';
    const text = formatCertificateDetails(parsed).trim();

    return {
        title: certificateTitle(index, visibleCertificates.length),
        details: parsed,
        text,
        error: text ? '' : error,
        placeholder: text || error ? '' : REGISTRATION_TEXT.noCertificateDetails,
    };
}

/** The authenticator data's own view: its title and the decoded data as JSON; null when there is none. */
export function describeAuthenticatorData(state) {
    const data = state.authenticatorData;
    if (!data) {
        return null;
    }
    return { title: REGISTRATION_TEXT.authenticatorData, text: JSON.stringify(data, null, 2) };
}

/**
 * What an advanced registration's answer gives its registration view: the
 * browser's attestation object and authenticator data, and the relying party's
 * certificates under any of their spellings.
 */
export function registrationResultInput(credentialJson, relyingPartyInfo) {
    return {
        attestationObjectValue: credentialJson?.response?.attestationObject || '',
        authenticatorDataValue: credentialJson?.response?.authenticatorData || '',
        fallbackCertificates: collectTruthyEntries(
            relyingPartyInfo?.attestationCertificate,
            relyingPartyInfo?.attestationCertificates,
            relyingPartyInfo?.attestation_certificate,
            relyingPartyInfo?.attestation_certificates,
            relyingPartyInfo?.registrationData?.attestationCertificate,
            relyingPartyInfo?.registrationData?.attestationCertificates,
            relyingPartyInfo?.registrationData?.attestation_certificate,
            relyingPartyInfo?.registrationData?.attestation_certificates,
        ),
    };
}

/**
 * The registration kept as data (schemaVersion 2): the decoded state, the
 * browser's response and the relying party's view of it. No markup.
 */
export function registrationSnapshotPayload({ stateSnapshot, credentialJson, relyingPartyCopy }, capturedAt) {
    return {
        schemaVersion: 2,
        capturedAt,
        state: stateSnapshot || {},
        response: {
            credential: credentialJson,
            relyingParty: relyingPartyCopy || null,
        },
    };
}
