// What the registration view shows, as data: the browser's response and its
// client data, the relying party's view of the registration, and the attestation
// (./describe.js describes each part). DOM-free. The state the view is built
// from is passed in (./state.js).
import {collectTruthyEntries} from './data-utils.js';
import {describeAttestationSection, describeClientData} from './describe.js';
import {hashAuthenticatorData, prepareRegistrationState} from './prepare.js';
import {applyRegistrationSnapshot, captureRegistrationState} from './state-snapshot.js';
import {sanitizeRelyingPartyInfo} from './sanitize.js';

/** @import { Decode, RegistrationSources, RegistrationState } from './state.js' */
/** @import { AttestationView } from './describe.js' */

/**
 * The registration's view: the response's three blocks as text, and the attestation.
 * @typedef {{ response: { credential: string, clientData: string, relyingParty: string }, attestation: AttestationView | null }} RegistrationView
 */

/**
 * The registration's view as data, and what its snapshot keeps. A saved
 * snapshot's state is shown as it is; otherwise the attestation object and the
 * authenticator data are decoded through `decode` into `state`.
 * @param {RegistrationSources & {
 *     credentialJson?: Record<string, any> | null,
 *     authenticatorDataHex?: string,
 *     fallbackClientData?: string | null,
 *     snapshotState?: Record<string, any> | null,
 * }} sources
 * @param {{ state: RegistrationState, decode: Decode }} steps
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
    preferFallbackCertificates = false,
    snapshotState = null,
} = {}, { state, decode }) {
    const clientDataDisplay = describeClientData(credentialJson, fallbackClientData);

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
 * What an advanced registration's answer gives its registration view: the
 * browser's attestation object and authenticator data, and the relying party's
 * certificates, at its root or in its registration data.
 */
export function registrationResultInput(credentialJson, relyingPartyInfo) {
    return {
        attestationObjectValue: credentialJson?.response?.attestationObject || '',
        authenticatorDataValue: credentialJson?.response?.authenticatorData || '',
        fallbackCertificates: collectTruthyEntries(
            relyingPartyInfo?.attestationCertificate,
            relyingPartyInfo?.attestationCertificates,
            relyingPartyInfo?.registrationData?.attestationCertificate,
            relyingPartyInfo?.registrationData?.attestationCertificates,
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
