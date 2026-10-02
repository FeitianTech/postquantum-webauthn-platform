export const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';
export const LEGACY_SIMPLE_STORAGE_KEY = 'postquantum-webauthn.simpleCredentials';
export const LEGACY_ADVANCED_STORAGE_KEY = 'postquantum-webauthn.advancedCredentials';

export const CERTIFICATE_COLLECTION_KEYS = [
    'attestationCertificate',
    'attestationCertificates',
];

// Stripped at any depth: the server's attestation checks name their authenticator
// data authenticator_data.
export const HEAVY_DUPLICATE_KEYS = [
    'attestationObject',
    'authenticatorData',
    'authenticator_data',
];

export const AGGRESSIVE_DROP_KEYS = [
    'attestationObject',
    'attestationStatement',
    'registrationResponse',
];

export const SERVER_ARTIFACT_VERSION = 1;

// What a saved record keeps that is heavy, and the registration markup an
// earlier version kept beside it.
export const LOCAL_HEAVY_ROOT_KEYS = [
    'attestationObject',
    'attestationStatement',
    'registrationResponse',
    'clientDataJSON',
    'authenticatorData',
    'authenticatorDataHex',
    'authenticatorDataHash',
    'registrationDetailHtml',
    'registrationDetailCombinedHtml',
    'registrationDetailCopy',
];

export const LOCAL_HEAVY_PROPERTY_KEYS = [
    'attestationCertificates',
    'attestationChecks',
];

export const LOCAL_HEAVY_RELYING_PARTY_KEYS = [
    'registrationData',
    'attestationCertificate',
    'attestationCertificates',
];

// A registration response or relying-party view longer than this, as JSON, is left
// out of a snapshot rather than cut: a cut value would no longer decode.
export const MAX_SNAPSHOT_RESPONSE_LENGTH = 120000;
export const MAX_DETAIL_STRING_LENGTH = 48000;
export const MAX_AUTH_DATA_HEX_LENGTH = 8192;
export const MAX_AUTH_DATA_HASH_LENGTH = 1024;

export const SNAPSHOT_CERT_STRIP_KEYS = [
    'derBase64',
];

