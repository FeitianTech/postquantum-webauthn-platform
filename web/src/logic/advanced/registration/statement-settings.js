// What an authenticator's metadata statement says that the Advanced
// registration's form can take, for "Try in Advanced" on its MDS entry:
// - the signature algorithms: getInfo's, the authenticator's own list in COSE
//   numbers (ML-DSA's included), else the statement's authenticationAlgorithms
//   by their FIDO registry names; only those the form offers, in its order;
// - user verification: required when the statement lists a way of verifying
//   the user, to exercise it, and discouraged when the authenticator can only
//   test presence;
// - the attachment: platform for an internal authenticator, cross-platform for
//   an external one, nothing when it says both or neither.
// Only FIDO2 and U2F authenticators register through WebAuthn (a U2F one through
// CTAP1); a UAF one gives nothing. DOM-free: the entry's page hands these to the
// Advanced tab, which sets them with its form's own setter.
import { ALGORITHM_OPTIONS } from './algorithm-options.js';

/**
 * @typedef {{
 *   algorithms?: number[],
 *   userVerification?: 'required' | 'discouraged',
 *   attachment?: 'platform' | 'cross-platform',
 * }} StatementSettings
 */

export const TRY_IN_ADVANCED_TEXT = {
    button: 'Try in Advanced',
    title: 'Open the Advanced registration, set for what this statement says',
    /** @param {string} name */
    filled: name => `The Advanced registration now asks for what the metadata of ${name} says.`,
};

const FAMILIES = new Set(['fido2', 'u2f']);

// The FIDO registry's names of the signature algorithms the form offers.
/** @type {Record<string, number>} */
const REGISTRY_ALGORITHMS = {
    secp256r1_ecdsa_sha256_raw: -7,
    secp256r1_ecdsa_sha256_der: -7,
    ed25519_eddsa_sha512_raw: -8,
    secp384r1_ecdsa_sha384_raw: -35,
    secp521r1_ecdsa_sha512_raw: -36,
    rsassa_pkcsv15_sha256_raw: -257,
    rsa_emsa_pkcs1_sha256_raw: -257,
    rsa_emsa_pkcs1_sha256_der: -257,
    rsassa_pkcsv15_sha384_raw: -258,
    rsassa_pkcsv15_sha512_raw: -259,
    rsassa_pkcsv15_sha1_raw: -65535,
    rsassa_pss_sha256_raw: -37,
    rsassa_pss_sha256_der: -37,
    rsassa_pss_sha384_raw: -38,
    rsassa_pss_sha512_raw: -39,
    secp256k1_ecdsa_sha256_raw: -47,
    secp256k1_ecdsa_sha256_der: -47,
    ed448_eddsa_sha512_raw: -53,
};

const PRESENCE_ONLY = new Set(['presence_internal', 'none']);
const EXTERNAL = new Set(['external', 'wired', 'wireless', 'nfc', 'bluetooth', 'network', 'wifi_direct']);

const listOf = value => (Array.isArray(value) ? value : []);

/** The form's algorithms among `algs`, in the form's order. */
const offered = algs => ALGORITHM_OPTIONS.map(option => option.alg).filter(alg => algs.includes(alg));

function statementAlgorithms(statement) {
    const getInfo = offered(listOf(statement.authenticatorGetInfo?.algorithms).map(entry => entry?.alg));
    if (getInfo.length) {
        return getInfo;
    }
    return offered(listOf(statement.authenticationAlgorithms).map(name => REGISTRY_ALGORITHMS[name]));
}

function statementUserVerification(details) {
    const alternatives = listOf(details).map(listOf).filter(methods => methods.length);
    if (!alternatives.length) {
        return null;
    }
    const verifies = alternatives.some(methods => methods.some(method => !PRESENCE_ONLY.has(method?.userVerificationMethod)));
    return verifies ? 'required' : 'discouraged';
}

function statementAttachment(hints) {
    const listed = listOf(hints);
    const internal = listed.includes('internal');
    const external = listed.some(hint => EXTERNAL.has(hint));
    if (internal === external) {
        return null;
    }
    return internal ? 'platform' : 'cross-platform';
}

/**
 * @param {Record<string, any> | null | undefined} statement An MDS entry's metadata statement.
 * @returns {StatementSettings | null} What the form can take from it, or null for nothing.
 */
export function statementSettings(statement) {
    if (!statement || typeof statement !== 'object' || !FAMILIES.has(statement.protocolFamily)) {
        return null;
    }
    /** @type {StatementSettings} */
    const settings = {};
    const algorithms = statementAlgorithms(statement);
    if (algorithms.length) {
        settings.algorithms = algorithms;
    }
    const userVerification = statementUserVerification(statement.userVerificationDetails);
    if (userVerification) {
        settings.userVerification = userVerification;
    }
    const attachment = statementAttachment(statement.attachmentHint);
    if (attachment) {
        settings.attachment = attachment;
    }
    return Object.keys(settings).length ? settings : null;
}
