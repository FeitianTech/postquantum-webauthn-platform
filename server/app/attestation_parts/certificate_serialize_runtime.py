from __future__ import annotations

import base64
import hashlib
import textwrap
from datetime import datetime
from typing import Any, Dict


def _serialize_attestation_certificate_fallback(
    cert_bytes: bytes, error: Exception
) -> Dict[str, Any]:
    """Return certificate metadata when DER parsing fails."""

    der_base64 = base64.b64encode(cert_bytes).decode("ascii")
    pem_body = "\n".join(textwrap.wrap(der_base64, 64))
    pem = f"-----BEGIN CERTIFICATE-----\n{pem_body}\n-----END CERTIFICATE-----"

    fingerprints = {
        "sha256": hashlib.sha256(cert_bytes).hexdigest(),
        "sha1": hashlib.sha1(cert_bytes).hexdigest(),
        "md5": hashlib.md5(cert_bytes).hexdigest(),
    }

    public_key_info, summary_entries = _build_unknown_public_key_info(cert_bytes, error)

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


def serialize_attestation_certificate(cert_bytes: bytes) -> Any:
    if not cert_bytes:
        return None

    try:
        certificate = x509.load_der_x509_certificate(cert_bytes)
    except Exception as exc:  # pragma: no cover - exercised in dedicated tests
        return _serialize_attestation_certificate_fallback(cert_bytes, exc)
    version_number = certificate.version.value + 1
    version_hex = f"0x{certificate.version.value:x}"

    not_valid_before = _certificate_datetime(certificate, "not_valid_before")
    not_valid_after = _certificate_datetime(certificate, "not_valid_after")

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
                "value": _serialize_extension_value(ext),
                "displayHeader": metadata.get("header"),
                "includeOidInHeader": True if include_oid is None else bool(include_oid),
            }
        )

    fingerprints = {
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "sha1": certificate.fingerprint(hashes.SHA1()).hex(),
        "md5": certificate.fingerprint(hashes.MD5()).hex(),
    }

    der_bytes = certificate.public_bytes(serialization.Encoding.DER)
    der_base64 = base64.b64encode(der_bytes).decode("ascii")
    pem_body = "\n".join(textwrap.wrap(der_base64, 64))
    pem = f"-----BEGIN CERTIFICATE-----\n{pem_body}\n-----END CERTIFICATE-----"

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

    fallback_public_key_summary = []
    try:
        public_key = certificate.public_key()
    except (UnsupportedAlgorithm, ValueError) as exc:
        public_key = None
        public_key_info, fallback_public_key_summary = _build_unknown_public_key_info(cert_bytes, exc)
    else:
        public_key_info = _serialize_public_key_info(public_key)

    signature_bytes = certificate.signature
    signature_lines = format_hex_bytes_lines(signature_bytes)
    signature_hex = signature_bytes.hex()
    signature_colon = colon_hex(signature_bytes)

    try:
        signature_hash_algorithm = certificate.signature_hash_algorithm
    except Exception:  # pragma: no cover - cryptography may raise if unavailable
        signature_hash_algorithm = None
    if signature_hash_algorithm is not None:
        hash_name = getattr(signature_hash_algorithm, "name", None)
        if not hash_name:
            hash_name = signature_hash_algorithm.__class__.__name__
        signature_hash = {"name": hash_name}
    else:
        signature_hash = None

    serial_decimal = str(certificate.serial_number)
    serial_hex = f"0x{certificate.serial_number:x}"

    summary = _build_certificate_summary(
        certificate,
        version_number=version_number,
        version_hex=version_hex,
        serial_decimal=serial_decimal,
        serial_hex=serial_hex,
        signature_algorithm=signature_algorithm,
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        public_key=public_key,
        fallback_public_key_summary=fallback_public_key_summary,
        extensions=extensions,
        signature_lines=signature_lines,
        fingerprints=fingerprints,
    )

    signature_details = {
        "algorithm": signature_algorithm,
        "hash": signature_hash,
        "hex": signature_hex,
        "colon": signature_colon,
        "lines": signature_lines,
        "oid": signature_algorithm_oid,
        "details": signature_algorithm_details,
    }
    algorithm_info = _derive_certificate_algorithm_info(signature_details)
    subject_common_names = _extract_common_names(certificate.subject)

    def _isoformat(value: datetime) -> str:
        return _ensure_utc_datetime(value).isoformat()

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
        "issuer": format_x509_name(certificate.issuer),
        "validity": {
            "notBefore": _isoformat(not_valid_before),
            "notAfter": _isoformat(not_valid_after),
        },
        "subject": format_x509_name(certificate.subject),
        "subjectCommonNames": subject_common_names,
        "publicKeyInfo": public_key_info,
        "algorithmInfo": algorithm_info,
        "extensions": extensions,
        "fingerprints": fingerprints,
        "signature": signature_details,
        "derBase64": der_base64,
        "pem": pem,
        "summary": summary,
    }
