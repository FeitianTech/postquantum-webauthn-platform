// What each part of the registration view shows, as data: the attestation
// section with its certificates, the client data, a certificate's own view and the
// authenticator data's. DOM-free; the state each is read from is passed in
// (./state.js). ./view.js composes them into the registration's view.
import {base64UrlToJson, base64UrlToUtf8String} from '../../shared/bytes.js';
import {normaliseCertificateEntryForModal, partitionCertificateEntries} from '../certificates/core.js';
import {formatCertificateDetails} from '../certificates/text.js';
import {normalizeClientDataString} from './data-utils.js';
import {visibleStateCertificates} from './state.js';
import {sanitiseAttestationObjectForDisplay} from './sanitize-attestation-object.js';

/** @import { RegistrationState } from './state.js' */

/**
 * "Attestation Information": the attestation object's body (its JSON, a
 * placeholder, or why it could not be decoded), a button per listed certificate,
 * whether there is authenticator data, and the messages.
 * @typedef {{ kind: 'json' | 'placeholder' | 'error', text: string }} AttestationBody
 * @typedef {object} AttestationView
 * @property {AttestationBody} body
 * @property {Array<{ index: number, title: string }>} certificates
 * @property {string} certificateMessage
 * @property {boolean} hasAuthenticatorData
 * @property {string} authenticatorError
 */

/**
 * A listed certificate's own view.
 * @typedef {object} CertificateView
 * @property {string} title
 * @property {Record<string, unknown>} details
 * @property {string} text
 * @property {string} error
 * @property {string} placeholder
 */

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

/** The decoded attestation object (JSON the decoder answered) as the view shows it, as JSON. */
export function attestationObjectJson(attestationObject, attestationFormatRaw, certificates) {
    return JSON.stringify(sanitiseAttestationObjectForDisplay(attestationObject, attestationFormatRaw, certificates), null, 2);
}

/**
 * "Attestation Information", or null when the registration has no attestation:
 * the attestation object's body (its JSON, or why there is none), a button per
 * certificate that parsed, "Authenticator Data" when there is some, and the
 * messages. Records in `state` which certificates the view lists.
 * @param {RegistrationState} state
 * @param {{
 *     attestationObjectValue?: string,
 *     attestationDecodeError?: string,
 *     attestationFormatRaw?: string,
 *     attestationStatement?: Record<string, any> | null,
 *     authenticatorDataValue?: string,
 *     authenticatorDecodeError?: string,
 * }} [parts]
 * @returns {AttestationView | null}
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

    /** @type {AttestationBody} */
    let body;
    if (attestationObject) {
        body = { kind: 'json', text: attestationObjectJson(attestationObject, attestationFormatRaw, certificatesAll) };
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
export function describeClientData(credentialJson, fallbackClientData) {
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
 * A listed certificate's own view (numbered from 0 in the list's order): its
 * title, its text, the parser's error when there is no text, or neither; and its
 * decoded details. Null when the view lists no such certificate.
 * @param {RegistrationState} state
 * @param {number} index
 * @returns {CertificateView | null}
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

/**
 * The authenticator data's own view: its title and the decoded data as JSON; null when there is none.
 * @param {RegistrationState} state
 * @returns {{ title: string, text: string } | null}
 */
export function describeAuthenticatorData(state) {
    const data = state.authenticatorData;
    if (!data) {
        return null;
    }
    return { title: REGISTRATION_TEXT.authenticatorData, text: JSON.stringify(data, null, 2) };
}
