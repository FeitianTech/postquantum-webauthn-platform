// A saved credential's details, as data: the sections above its registration
// (./detail-sections.js) and the registration's own view (../registration-view.js),
// composed into `state` (../registration-state.js) from the record, its saved
// snapshot, or the decoder (`decode`). DOM-free: the credential's details dialog
// builds from it.
import {extractCredentialAttestationContext} from '../attestation-context.js';
import {resetRegistrationState} from '../registration-state.js';
import {composeRegistration} from '../registration-view.js';
import {
    describeAaguid,
    describeAttestationFormat,
    describeAuthenticatorDataFlags,
    describeExtensions,
    describeProperties,
    describePublicKey,
    describeUserInfo,
} from './detail-sections.js';
import {pickFirstString} from './helpers.js';
import {buildRegistrationContext} from './registration-context.js';
import {
    readSnapshotResponse,
    resolveRegistrationSnapshotContext,
} from './snapshot-context.js';

/**
 * Whether the record must first be completed from its server artifact: an
 * advanced one whose snapshot does not hold the registration as data (an older
 * one lacks the response the sections are built from).
 */
export function needsArtifact(cred) {
    return cred.type !== 'simple' && !readSnapshotResponse(cred.registrationDetailSnapshot);
}

/**
 * Everything a credential's details show, in their order: `sections` (Properties,
 * User info with its AAGUID, Attestation Format, then Authenticator Data,
 * extensions and Public Key when the record has them) and `registration`.
 * describers: describeCoseAlgorithm, describeCoseKeyType, describeMldsaParameterSet.
 */
export async function composeCredentialDetail(cred, { state, decode, describers }) {
    resetRegistrationState(state);

    const {
        detailPreparation,
        snapshotState,
        snapshotResponse,
    } = resolveRegistrationSnapshotContext(cred, state);

    const {
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
    } = buildRegistrationContext(cred, {
        snapshotState,
        detailPreparation,
    });

    const registration = await composeRegistration({
        // Never empty: the context gives it a type and a response.
        credentialJson: snapshotResponse?.credential || registrationCredential,
        relyingPartyInfo: snapshotResponse?.relyingParty || relyingPartyInfo,
        attestationObjectValue,
        attestationObjectDecoded,
        authenticatorDataValue: authenticatorDataForDetail,
        authenticatorDataHex,
        fallbackCertificates,
        fallbackClientData: fallbackClientDataString,
        fallbackParsedClientData: fallbackClientDataObject,
        preferFallbackCertificates: Array.isArray(fallbackCertificates) && fallbackCertificates.length > 0,
        snapshotState: snapshotResponse ? snapshotState : null,
    }, { state, decode });

    const attestationFormatRaw = pickFirstString(
        cred.attestationFormat,
        cred.attestationFmt,
        relyingPartyInfo?.attestationFmt,
        attestationObjectDecoded && typeof attestationObjectDecoded.fmt === 'string'
            ? attestationObjectDecoded.fmt
            : '',
    );

    const attestationContext = extractCredentialAttestationContext(cred);

    return {
        properties: describeProperties({
            cred,
            attestationContext,
            fallbackCertificates,
            certificateAaguidHex,
            authDataAaguidHex,
        }),
        userInfo: describeUserInfo(cred),
        aaguid: describeAaguid(cred, attestationContext),
        attestationFormat: describeAttestationFormat(attestationFormatRaw || 'none'),
        authenticatorData: describeAuthenticatorDataFlags(cred),
        extensions: describeExtensions(cred),
        publicKey: describePublicKey(cred, describers),
        registration,
    };
}
