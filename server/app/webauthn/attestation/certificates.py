from __future__ import annotations

import hashlib
import logging
import textwrap
from collections.abc import Mapping
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization

from fido2.cose import (
    describe_mldsa_oid,
    describe_mldsa_oid_name,
)
from fido2.utils import ByteBuffer
from fido2.webauthn import RegistrationResponse

from ... import encoding
from ...encoding import encode_base64
from . import (
    certificate_extensions,
    certificate_names,
    certificate_public_keys,
    certificate_summary,
    formatting,
    trust,
)
from .constants import EXTENSION_DISPLAY_METADATA

logger = logging.getLogger(__name__)


def _pem(der_base64: str) -> str:
    pem_body = "\n".join(textwrap.wrap(der_base64, 64))
    return f"-----BEGIN CERTIFICATE-----\n{pem_body}\n-----END CERTIFICATE-----"


def _serialize_attestation_certificate_fallback(
    cert_bytes: bytes, error: Exception
) -> dict[str, Any]:
    """Return certificate metadata when DER parsing fails."""

    der_base64 = encode_base64(cert_bytes)
    pem = _pem(der_base64)

    fingerprints = {
        "sha256": hashlib.sha256(cert_bytes).hexdigest(),
        "sha1": hashlib.sha1(cert_bytes).hexdigest(),
        "md5": hashlib.md5(cert_bytes).hexdigest(),
    }

    public_key_info, summary_entries = certificate_public_keys._build_unknown_public_key_info(cert_bytes, error)

    summary_lines = [
        "Unable to parse attestation certificate using cryptography.x509.",
        f"Error: {error}",
        "",
        f"DER length: {len(cert_bytes)} bytes",
        "",
        "Fingerprints:",
        f"    SHA256: {fingerprints['sha256']}",
        f"    SHA1: {fingerprints['sha1']}",
        f"    MD5: {fingerprints['md5']}",
    ]

    if summary_entries:
        summary_lines.append("")
        summary_lines.append("Best-effort public key details:")
        for label, value in summary_entries:
            if value in (None, ""):
                continue
            if isinstance(value, list):
                summary_lines.append(f"    {label}:")
                for item in value:
                    summary_lines.append(f"        {item}")
            else:
                summary_lines.append(f"    {label}: {value}")

    summary = "\n".join(summary_lines).strip()

    return {
        "error": f"Unable to parse attestation certificate: {error}",
        "derBase64": der_base64,
        "fingerprints": fingerprints,
        "pem": pem,
        "publicKeyInfo": public_key_info,
        "raw": cert_bytes.hex(),
        "summary": summary,
        "parseError": str(error),
    }


def _extension_entries(certificate: Any) -> list[dict[str, Any]]:
    extensions = []
    for ext in certificate.extensions:
        oid = ext.oid.dotted_string
        metadata = EXTENSION_DISPLAY_METADATA.get(oid, {})
        metadata_friendly = metadata.get("friendly_name")
        default_name = getattr(ext.oid, "_name", None)
        include_oid = metadata.get("include_oid_in_header")
        extensions.append(
            {
                "oid": oid,
                "name": metadata_friendly or default_name or oid,
                "friendlyName": metadata_friendly,
                "critical": ext.critical,
                "value": certificate_extensions._serialize_extension_value(ext),
                "displayHeader": metadata.get("header"),
                "includeOidInHeader": True if include_oid is None else bool(include_oid),
            }
        )
    return extensions


def _signature_algorithm(certificate: Any) -> tuple[Any, Any, Any]:
    """The signature algorithm's OID, display name (ML-DSA's friendly name) and ML-DSA details."""

    signature_algorithm_oid = getattr(
        certificate.signature_algorithm_oid,
        "dotted_string",
        None,
    )
    raw_signature_algorithm = getattr(
        certificate.signature_algorithm_oid,
        "_name",
        signature_algorithm_oid,
    )
    if isinstance(raw_signature_algorithm, str) and raw_signature_algorithm.lower() == "unknown oid":
        signature_algorithm = signature_algorithm_oid or raw_signature_algorithm
    else:
        signature_algorithm = raw_signature_algorithm

    signature_algorithm_details = describe_mldsa_oid(signature_algorithm_oid)
    friendly_signature_name = describe_mldsa_oid_name(signature_algorithm_oid)
    if friendly_signature_name:
        signature_algorithm = friendly_signature_name
    return signature_algorithm_oid, signature_algorithm, signature_algorithm_details


def _public_key_view(certificate: Any, cert_bytes: bytes) -> tuple[Any, dict[str, Any], list[tuple[str, Any]]]:
    """The loaded key (``None`` if cryptography cannot load it), its description, and the fallback summary."""

    fallback_public_key_summary: list[tuple[str, Any]] = []
    try:
        public_key = certificate.public_key()
    except (UnsupportedAlgorithm, ValueError) as exc:
        public_key = None
        public_key_info, fallback_public_key_summary = certificate_public_keys._build_unknown_public_key_info(
            cert_bytes, exc
        )
    else:
        public_key_info = certificate_public_keys._serialize_public_key_info(public_key)
    return public_key, public_key_info, fallback_public_key_summary


def _signature_hash(certificate: Any) -> dict[str, Any] | None:
    try:
        signature_hash_algorithm = certificate.signature_hash_algorithm
    except Exception:  # pragma: no cover - cryptography may raise if unavailable
        signature_hash_algorithm = None
    if signature_hash_algorithm is None:
        return None
    hash_name = getattr(signature_hash_algorithm, "name", None)
    if not hash_name:
        hash_name = signature_hash_algorithm.__class__.__name__
    return {"name": hash_name}


def _signature_view(certificate: Any, oid: Any, algorithm: Any, details: Any) -> dict[str, Any]:
    signature_bytes = certificate.signature
    return {
        "algorithm": algorithm,
        "hash": _signature_hash(certificate),
        "hex": signature_bytes.hex(),
        "colon": formatting.colon_hex(signature_bytes),
        "lines": formatting.format_hex_bytes_lines(signature_bytes),
        "oid": oid,
        "details": details,
    }


def serialize_attestation_certificate(cert_bytes: bytes) -> Any:
    if not cert_bytes:
        return None

    try:
        certificate = x509.load_der_x509_certificate(cert_bytes)
    except Exception as exc:  # pragma: no cover - exercised in dedicated tests
        return _serialize_attestation_certificate_fallback(cert_bytes, exc)
    version_number = certificate.version.value + 1
    version_hex = f"0x{certificate.version.value:x}"

    not_valid_before = trust._certificate_datetime(certificate, "not_valid_before")
    not_valid_after = trust._certificate_datetime(certificate, "not_valid_after")

    extensions = _extension_entries(certificate)

    fingerprints = {
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "sha1": certificate.fingerprint(hashes.SHA1()).hex(),
        "md5": certificate.fingerprint(hashes.MD5()).hex(),
    }

    der_base64 = encode_base64(certificate.public_bytes(serialization.Encoding.DER))
    signature_algorithm_oid, signature_algorithm, signature_algorithm_details = _signature_algorithm(certificate)
    public_key, public_key_info, fallback_public_key_summary = _public_key_view(certificate, cert_bytes)
    signature_details = _signature_view(
        certificate, signature_algorithm_oid, signature_algorithm, signature_algorithm_details
    )
    signature_lines = signature_details["lines"]

    summary = certificate_summary._build_certificate_summary(
        certificate,
        version_number=version_number,
        version_hex=version_hex,
        serial_decimal=str(certificate.serial_number),
        serial_hex=f"0x{certificate.serial_number:x}",
        signature_algorithm=signature_algorithm,
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        public_key=public_key,
        fallback_public_key_summary=fallback_public_key_summary,
        extensions=extensions,
        signature_lines=signature_lines,
        fingerprints=fingerprints,
    )

    return {
        "version": {
            "display": f"{version_number} ({version_hex})",
            "numeric": version_number,
            "hex": version_hex,
        },
        "serialNumber": {
            "decimal": str(certificate.serial_number),
            "hex": f"0x{certificate.serial_number:x}",
        },
        "signatureAlgorithm": signature_algorithm,
        "signatureAlgorithmOid": signature_algorithm_oid,
        "signatureAlgorithmDetails": signature_algorithm_details,
        "issuer": certificate_names.format_x509_name(certificate.issuer),
        "validity": {
            "notBefore": trust._ensure_utc_datetime(not_valid_before).isoformat(),
            "notAfter": trust._ensure_utc_datetime(not_valid_after).isoformat(),
        },
        "subject": certificate_names.format_x509_name(certificate.subject),
        "subjectCommonNames": certificate_names._extract_common_names(certificate.subject),
        "publicKeyInfo": public_key_info,
        "algorithmInfo": certificate_names._derive_certificate_algorithm_info(signature_details),
        "extensions": extensions,
        "fingerprints": fingerprints,
        "signature": signature_details,
        "derBase64": der_base64,
        "pem": _pem(der_base64),
        "summary": summary,
    }


def _coerce_attestation_certificate_bytes(value: Any) -> bytes | None:
    """Return raw certificate bytes for attestation payload *value*."""

    if value in (None, ""):
        return None

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, ByteBuffer):
        return value.getvalue()

    if isinstance(value, str):
        if not value.strip():
            return None
        decoded = encoding.try_decode_base64(value)
        if decoded is None:
            decoded = encoding.try_decode_base64url(value)
        return decoded

    if isinstance(value, Mapping):
        raw_value = value.get("raw")
        if isinstance(raw_value, str):
            decoded = encoding.try_decode_hex(raw_value)
            if decoded is not None:
                return decoded

        der_base64 = value.get("derBase64") or value.get("der_base64")
        if isinstance(der_base64, str):
            decoded = encoding.try_decode_base64(der_base64)
            if decoded is not None:
                return decoded

        pem_value = value.get("pem")
        if isinstance(pem_value, str):
            try:
                return encoding.decode_pem_body(pem_value)
            except encoding.EncodingError:
                pass

    try:
        return bytes(value)
    except (TypeError, ValueError):
        return None


def _no_attestation_details() -> tuple[str, dict[str, Any], None, None, dict[str, Any], None, list[dict[str, Any]]]:
    return "none", {}, None, None, {}, None, []


def _serialized_certificate_chain(attestation_statement: Any) -> list[dict[str, Any]]:
    """Each x5c certificate serialised, or an error entry where it cannot be."""

    attestation_certificates: list[dict[str, Any]] = []
    if not isinstance(attestation_statement, Mapping):
        return attestation_certificates
    cert_chain = attestation_statement.get("x5c") or []
    if not (isinstance(cert_chain, (list, tuple)) and cert_chain):
        return attestation_certificates

    for entry in cert_chain:
        certificate_bytes = _coerce_attestation_certificate_bytes(entry)
        if certificate_bytes is None:
            attestation_certificates.append({
                "error": "Unable to decode attestation certificate bytes.",
            })
            continue

        try:
            certificate_details = serialize_attestation_certificate(certificate_bytes)
        except Exception as cert_error:  # pragma: no cover - defensive
            certificate_details = {"error": str(cert_error)}
        else:
            if certificate_details is None:
                certificate_details = {
                    "error": "Unable to parse attestation certificate.",
                }

        attestation_certificates.append(certificate_details)
    return attestation_certificates


def _client_extension_results(registration: Any) -> dict[str, Any]:
    extension_outputs = registration.client_extension_results
    if not extension_outputs:
        return {}
    if isinstance(extension_outputs, dict):
        return extension_outputs
    if isinstance(extension_outputs, Mapping):
        return dict(extension_outputs)
    return extension_outputs  # type: ignore[return-value]


def extract_attestation_details(
    response: Any,
) -> tuple[
    str,
    dict[str, Any],
    str | None,
    str | None,
    dict[str, Any],
    dict[str, Any] | None,
    list[dict[str, Any]],
]:
    """Parse attestation information from a registration response structure."""

    if not isinstance(response, dict):
        return _no_attestation_details()

    try:
        registration = RegistrationResponse.from_dict(response)
    except Exception as exc:
        # The caller's registration data, not a server fault: debug, not stdout.
        logger.debug("Failed to parse registration response for attestation: %s", exc)
        return _no_attestation_details()

    attestation_object = registration.response.attestation_object
    attestation_format = getattr(attestation_object, "fmt", None) or "none"
    attestation_statement = attestation_object.att_stmt or {}
    attestation_object_b64 = formatting.encode_base64url(bytes(attestation_object))

    attestation_certificates = _serialized_certificate_chain(attestation_statement)
    attestation_certificate = attestation_certificates[0] if attestation_certificates else None

    client_data = registration.response.client_data
    client_data_b64 = getattr(client_data, "b64", None)
    if client_data_b64 is None:
        client_data_b64 = formatting.encode_base64url(bytes(client_data))

    return (
        attestation_format,
        attestation_statement,
        attestation_object_b64,
        client_data_b64,
        _client_extension_results(registration),
        attestation_certificate,
        attestation_certificates,
    )
