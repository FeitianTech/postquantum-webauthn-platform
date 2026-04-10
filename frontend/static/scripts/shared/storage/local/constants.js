export const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';
export const LEGACY_SIMPLE_STORAGE_KEY = 'postquantum-webauthn.simpleCredentials';
export const LEGACY_ADVANCED_STORAGE_KEY = 'postquantum-webauthn.advancedCredentials';

export const CERTIFICATE_COLLECTION_KEYS = [
    'attestationCertificate',
    'attestationCertificates',
    'attestation_certificate',
    'attestation_certificates',
];

export const HEAVY_DUPLICATE_KEYS = [
    'attestationObject',
    'attestation_object',
    'authenticatorData',
    'authenticator_data',
];

export const AGGRESSIVE_DROP_KEYS = [
    'attestationObject',
    'attestation_object',
    'attestationStatement',
    'attestation_statement',
    'registrationResponse',
    'registration_response',
];

export const SERVER_ARTIFACT_VERSION = 1;

export const LOCAL_HEAVY_ROOT_KEYS = [
    'attestationObject',
    'attestation_object',
    'attestationObjectRaw',
    'attestation_object_raw',
    'attestationObjectDecoded',
    'attestation_object_decoded',
    'attestationStatement',
    'attestation_statement',
    'attestationCertificate',
    'attestation_certificate',
    'attestationCertificates',
    'attestation_certificates',
    'attestationCertificatesDetails',
    'attestation_certificates_details',
    'registrationResponse',
    'registration_response',
    'registrationCredential',
    'registration_credential',
    'registrationResult',
    'registration_result',
    'registrationDetailHtml',
    'registration_detail_html',
    'registrationDetailCombinedHtml',
    'registration_detail_combined_html',
    'registrationDetailCopy',
    'registration_detail_copy',
    'registrationData',
    'registration_data',
    'clientDataJSON',
    'clientData',
    'clientDataParsed',
    'clientDataObject',
    'client_data_json',
    'authenticatorData',
    'authenticator_data',
    'authenticatorDataHex',
    'authenticator_data_hex',
    'authenticatorDataHash',
    'authenticator_data_hash',
];

export const LOCAL_HEAVY_PROPERTY_KEYS = [
    'attestationCertificate',
    'attestationCertificates',
    'attestation_certificate',
    'attestation_certificates',
    'attestationChecks',
    'attestation_checks',
    'registrationData',
    'registration_data',
];

export const LOCAL_HEAVY_RELYING_PARTY_KEYS = [
    'registrationData',
    'registration_data',
    'attestationCertificate',
    'attestationCertificates',
    'attestation_certificate',
    'attestation_certificates',
];

export const MAX_SNAPSHOT_HTML_LENGTH = 120000;
export const MAX_DETAIL_STRING_LENGTH = 48000;
export const MAX_AUTH_DATA_HEX_LENGTH = 8192;
export const MAX_AUTH_DATA_HASH_LENGTH = 1024;

export const SNAPSHOT_CERT_STRIP_KEYS = [
    'der',
    'derBase64',
    'der_base64',
    'certificatePem',
    'certificate_pem',
    'certificateDer',
    'certificate_der',
    'certificate',
    'certificate_raw',
    'certificateRaw',
    'rawBinary',
    'raw_buffer',
    'rawBuffer',
    'rawBytes',
    'raw_bytes',
];

export const SNAPSHOT_EXTENSION_STRIP_KEYS = [
    'raw',
    'rawHex',
    'raw_hex',
    'hex',
    'valueHex',
    'value_hex',
    'der',
    'derBase64',
    'der_base64',
];

export const SNAPSHOT_ATTESTATION_STRIP_KEYS = [
    'attestationCertificate',
    'attestationCertificates',
    'attestation_certificate',
    'attestation_certificates',
];

export const SNAPSHOT_AUTH_DATA_STRIP_KEYS = [
    'rawBinary',
    'raw_buffer',
    'rawBuffer',
    'rawBytes',
    'raw_bytes',
];
