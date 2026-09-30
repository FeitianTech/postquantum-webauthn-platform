from __future__ import annotations

# Where an advanced ceremony's challenge came from: the server issued it and kept
# the state in the session.
CHALLENGE_SOURCE_SERVER = "server-session"

HEAVY_CREDENTIAL_KEYS: set[str] = {
    "attestationObject",
    "attestation_object",
    "attestationObjectRaw",
    "attestation_object_raw",
    "attestationObjectDecoded",
    "attestation_object_decoded",
    "attestationStatement",
    "attestation_statement",
    "attestationCertificate",
    "attestation_certificate",
    "attestationCertificates",
    "attestation_certificates",
    "attestationCertificatesDetails",
    "attestation_certificates_details",
    "registrationResponse",
    "registration_response",
    "registrationCredential",
    "registration_credential",
    "registrationResult",
    "registration_result",
    "registrationDetailSnapshot",
    "registration_detail_snapshot",
    "registrationDetailHtml",
    "registration_detail_html",
    "registrationDetailCombinedHtml",
    "registration_detail_combined_html",
    "registrationDetailCopy",
    "registration_detail_copy",
    "registrationData",
    "registration_data",
    "clientDataJSON",
    "clientData",
    "clientDataParsed",
    "clientDataObject",
    "client_data_json",
    "authenticatorData",
    "authenticator_data",
    "authenticatorDataHex",
    "authenticator_data_hex",
    "authenticatorDataHash",
    "authenticator_data_hash",
}

HEAVY_PROPERTY_KEYS: set[str] = {
    "attestationCertificate",
    "attestationCertificates",
    "attestation_certificate",
    "attestation_certificates",
    "attestationChecks",
    "attestation_checks",
    "registrationData",
    "registration_data",
}

HEAVY_RELYING_PARTY_KEYS: set[str] = {
    "registrationData",
    "registration_data",
    "attestationCertificate",
    "attestationCertificates",
    "attestation_certificate",
    "attestation_certificates",
}
