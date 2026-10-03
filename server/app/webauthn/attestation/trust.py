from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography import x509
from flask import current_app

from ... import encoding, json_values
from . import formatting
from .constants import AAGUID_EXTENSION_OID, UNREADABLE_EXTENSIONS


def _trusted_ca_subjects() -> set[str] | None:
    subjects = current_app.config.get("TRUSTED_ATTESTATION_CA_SUBJECTS")
    if isinstance(subjects, set):
        return subjects
    if isinstance(subjects, (list, tuple)):
        return {str(subject) for subject in subjects if subject}
    return None


def _trusted_ca_fingerprints() -> set[str] | None:
    fingerprints = current_app.config.get("TRUSTED_ATTESTATION_CA_FINGERPRINTS")
    if isinstance(fingerprints, set):
        return {str(fp).upper() for fp in fingerprints if fp}
    if isinstance(fingerprints, (list, tuple)):
        return {str(fp).upper() for fp in fingerprints if fp}
    return None


def _certificate_fingerprint(cert_bytes: bytes) -> str:
    return hashlib.sha256(cert_bytes).hexdigest().upper()


def _is_trusted_ca_certificate(cert_bytes: bytes, *, allow_subject_parsing: bool = True) -> bool:
    subjects = _trusted_ca_subjects()
    fingerprints = _trusted_ca_fingerprints()

    if not subjects and not fingerprints:
        return True

    if fingerprints:
        fingerprint = _certificate_fingerprint(cert_bytes)
        if fingerprint in fingerprints:
            return True

    if allow_subject_parsing and subjects:
        try:
            subject_value = x509.load_der_x509_certificate(cert_bytes).subject.rfc4514_string()
        except Exception:
            # Not a certificate, or a subject cryptography will not read.
            return False
        if subject_value in subjects:
            return True

    return False


def _collect_trust_path_entries(x5c: Any) -> list[bytes]:
    """Coerce an ``x5c`` attestation entry into a list of DER certificates."""

    if not isinstance(x5c, Sequence):
        return []

    trust_path: list[bytes] = []
    for entry in x5c:
        data = json_values.as_bytes(entry)
        if data:
            trust_path.append(data)
    return trust_path


def _extract_certificate_aaguid(cert_der: bytes) -> bytes:
    """Return the AAGUID extension value from *cert_der* when present."""

    if not cert_der:
        return b""

    try:
        certificate = x509.load_der_x509_certificate(cert_der)
    except Exception:
        return b""

    try:
        extension = certificate.extensions.get_extension_for_oid(AAGUID_EXTENSION_OID)
    except (x509.ExtensionNotFound, *UNREADABLE_EXTENSIONS):
        return b""

    # cryptography has no type for FIDO's AAGUID extension: it is always unrecognised, its value the DER.
    raw_value = bytes(extension.value.value)
    decoded = formatting.der_octet_string_content(raw_value)
    if len(decoded) == 16:
        return decoded
    if len(raw_value) == 16:
        return raw_value
    return b""


def _coerce_certificate_bytes(value: Any) -> bytes | None:
    """Decode certificate data from common encodings into raw DER bytes."""

    byte_value = json_values.as_bytes(value)
    if byte_value is not None:
        return byte_value

    if isinstance(value, str):
        if not value.strip():
            return None
        decoded = encoding.try_decode_base64(value)
        if decoded is None:
            decoded = encoding.try_decode_hex(value)
        return decoded
    return None


def _collect_metadata_root_certificates(metadata_entry: Any) -> list[bytes]:
    """Extract attestation root certificates from a metadata entry."""

    roots: list[bytes] = []
    metadata_statement = getattr(metadata_entry, "metadata_statement", None)
    candidates: Any = None
    if metadata_statement is not None:
        candidates = getattr(
            metadata_statement,
            "attestation_root_certificates",
            None,
        )
        if not candidates and isinstance(metadata_statement, Mapping):
            candidates = metadata_statement.get(
                "attestation_root_certificates",
            ) or metadata_statement.get("attestationRootCertificates")

    if candidates is None and isinstance(metadata_entry, Mapping):
        candidates = metadata_entry.get(
            "attestation_root_certificates",
        ) or metadata_entry.get("attestationRootCertificates")

    if isinstance(candidates, (list, tuple, set)):
        iterable = candidates
    elif candidates is None:
        iterable = []
    else:
        iterable = [candidates]

    for candidate in iterable:
        data = _coerce_certificate_bytes(candidate)
        if data:
            roots.append(data)
    return roots


def _resolve_root_validity(checks: Mapping[str, bool | None]) -> bool | None:
    """Normalise root validity so red is only shown after explicit failures."""

    trusted = checks.get("trusted_ca")
    outcomes = [checks.get("chain"), checks.get("fido_mds")]
    attempted = [value for value in outcomes if value is not None]

    if trusted is True:
        if any(value is True for value in attempted):
            return True
        if len(attempted) == len(outcomes) and all(value is False for value in attempted):
            return False
        return None

    if trusted is False:
        if any(value is True for value in attempted):
            return True
        if attempted and all(value is False for value in attempted):
            return False
        return None

    return None
