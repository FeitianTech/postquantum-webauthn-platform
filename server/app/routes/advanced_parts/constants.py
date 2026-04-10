from __future__ import annotations

import re
from typing import Dict, Set

COSE_ALGORITHM_NAME_MAP: Dict[str, int] = {
    "ML-DSA-87": -50,
    "ML-DSA-65": -49,
    "ML-DSA-44": -48,
    "EDDSA": -8,
    "ED25519": -19,
    "ED448": -53,
    "ES256": -7,
    "ECDSA256": -7,
    "ECDSA-256": -7,
    "ES256K": -47,
    "ESP256": -9,
    "ESP-256": -9,
    "ES384": -35,
    "ES512": -36,
    "ESP384": -51,
    "ESP-384": -51,
    "ESP512": -52,
    "ESP-512": -52,
    "RS256": -257,
    "RSA256": -257,
    "RS384": -258,
    "RSA384": -258,
    "RS512": -259,
    "RSA512": -259,
    "RS1": -65535,
    "RSASSA-PKCS1-V1_5-SHA1": -65535,
    "PS256": -37,
    "PS384": -38,
    "PS512": -39,
}


def _normalize_algorithm_name_key_seed(name: str) -> str:
    base = name.strip().split("(")[0]
    if not base:
        return ""
    sanitized = re.sub(r"[^A-Z0-9]", "", base.upper())
    if sanitized.startswith("FIDOALG"):
        sanitized = sanitized[len("FIDOALG"):]
    if sanitized.startswith("COSEALG"):
        sanitized = sanitized[len("COSEALG"):]
    return sanitized


COSE_ALGORITHM_NAME_LOOKUP: Dict[str, int] = {}
for _raw_name, _alg_id in COSE_ALGORITHM_NAME_MAP.items():
    _normalized_key = _normalize_algorithm_name_key_seed(_raw_name)
    if _normalized_key:
        COSE_ALGORITHM_NAME_LOOKUP[_normalized_key] = _alg_id

COSE_ALGORITHM_NUMERIC_PATTERN = re.compile(r"-?\d+")

HEAVY_CREDENTIAL_KEYS: Set[str] = {
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

HEAVY_PROPERTY_KEYS: Set[str] = {
    "attestationCertificate",
    "attestationCertificates",
    "attestation_certificate",
    "attestation_certificates",
    "attestationChecks",
    "attestation_checks",
    "registrationData",
    "registration_data",
}

HEAVY_RELYING_PARTY_KEYS: Set[str] = {
    "registrationData",
    "registration_data",
    "attestationCertificate",
    "attestationCertificates",
    "attestation_certificate",
    "attestation_certificates",
}
