// A saved credential's details, as data: the sections above its registration
// (./sections.js) and the registration's own view (../registration/view.js),
// composed into a state of their own (../registration/state.js) from the record,
// its saved snapshot, or the server's decoder (../registration/decode-payload.js).
// DOM-free: the credential's details dialog builds from it.
import {extractCredentialAttestationContext} from '../attestation-context.js';
import {describeCoseAlgorithm, describeCoseKeyType, describeMldsaParameterSet} from '../cose-labels.js';
import {decodePayloadThroughApi} from '../registration/decode-payload.js';
import {createRegistrationState} from '../registration/state.js';
import {composeRegistration} from '../registration/view.js';
import {
    describeAaguid,
    describeAttestationFormat,
    describeAuthenticatorDataFlags,
    describeExtensions,
    describeProperties,
    describePublicKey,
    describeUserInfo,
} from './sections.js';
import {pickFirstString} from './registration-fields.js';
import {buildRegistrationContext} from './registration-context.js';
import {
    readSnapshotResponse,
    resolveRegistrationSnapshotContext,
} from './snapshot-context.js';

/** @import { RegistrationState } from '../registration/state.js' */
/** @import { RegistrationView } from '../registration/view.js' */
/** @import { DetailSectionsView } from './sections.js' */

/**
 * Everything a credential's details show.
 * @typedef {DetailSectionsView & { registration: RegistrationView }} CredentialDetail
 */

/**
 * Whether the record must first be completed from its server artifact: an
 * advanced one whose snapshot does not hold the registration as data (an older
 * one lacks the response the sections are built from).
 * @param {Record<string, any>} cred
 * @returns {boolean}
 */
export function needsArtifact(cred) {
    return cred.type !== 'simple' && !readSnapshotResponse(cred.registrationDetailSnapshot);
}

/**
 * Everything a credential's details show, in their order: the sections
 * (Properties, User info with its AAGUID, Attestation Format, then Authenticator
 * Data, extensions and Public Key when the record has them) and `registration`;
 * and the registration state it was composed into, which the details' levels read.
 * @param {Record<string, any>} cred
 * @returns {Promise<{ detail: CredentialDetail, state: RegistrationState }>}
 */
export async function composeCredentialDetail(cred) {
    const state = createRegistrationState();

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
        preferFallbackCertificates: Array.isArray(fallbackCertificates) && fallbackCertificates.length > 0,
        snapshotState: snapshotResponse ? snapshotState : null,
    }, { state, decode: decodePayloadThroughApi });

    const attestationFormatRaw = pickFirstString(
        cred.attestationFormat,
        cred.attestationFmt,
        relyingPartyInfo?.attestationFmt,
        attestationObjectDecoded && typeof attestationObjectDecoded.fmt === 'string'
            ? attestationObjectDecoded.fmt
            : '',
    );

    const attestationContext = extractCredentialAttestationContext(cred);

    /** @type {CredentialDetail} */
    const detail = {
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
        publicKey: describePublicKey(cred, { describeCoseAlgorithm, describeCoseKeyType, describeMldsaParameterSet }),
        registration,
    };
    return { detail, state };
}
