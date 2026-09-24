"""The OpenSSL-style text summary of a certificate.

Each section (header, validity, subject, public key, extensions, signature,
fingerprints, subject key identifier) is its own list of lines; a section with
nothing to say is left out, and sections are separated by one blank line.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from . import certificate_names, formatting, trust


def _isoformat(value: datetime) -> str:
    return trust._ensure_utc_datetime(value).isoformat()


def _public_key_entries(public_key: Any, fallback_public_key_summary: Sequence[tuple[str, Any]]) -> list[tuple[str, Any]]:
    """Label/value pairs for the key: the loadable types' own, else the best-effort summary."""

    pk_summary_entries: list[tuple[str, Any]] = []
    if public_key is None:
        pk_summary_entries.extend(fallback_public_key_summary)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        pk_summary_entries.append(("Type", "ECC"))
        if public_key.key_size:
            pk_summary_entries.append(("Public-Key", f"({public_key.key_size} bit)"))
        ecc_point_lines = formatting.format_hex_bytes_lines(
            public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
        )
        if ecc_point_lines:
            pk_summary_entries.append(("pub", ecc_point_lines))
        curve_name = getattr(public_key.curve, "name", None)
        if curve_name:
            pk_summary_entries.append(("Curve", curve_name))
    elif isinstance(public_key, rsa.RSAPublicKey):
        pk_summary_entries.append(("Type", "RSA"))
        if public_key.key_size:
            pk_summary_entries.append(("Public-Key", f"({public_key.key_size} bit)"))
        numbers = public_key.public_numbers()
        modulus_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        modulus_lines = formatting.format_hex_bytes_lines(modulus_bytes)
        if modulus_lines:
            pk_summary_entries.append(("Modulus", modulus_lines))
        pk_summary_entries.append(("Exponent", str(numbers.e)))
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_type = "Ed25519" if isinstance(public_key, ed25519.Ed25519PublicKey) else "Ed448"
        pk_summary_entries.append(("Type", key_type))
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        raw_lines = formatting.format_hex_bytes_lines(raw_bytes)
        if raw_lines:
            pk_summary_entries.append(("Public Key", raw_lines))
    else:
        pk_summary_entries.append(("Type", public_key.__class__.__name__))
    return pk_summary_entries


def _public_key_section(entries: Sequence[tuple[str, Any]]) -> list[str]:
    if not entries:
        return []
    lines = ["Subject Public Key Info:"]
    for label, value in entries:
        if value is None or (isinstance(value, list) and not value):
            continue
        if isinstance(value, list):
            lines.append(f"    {label}:")
            for line in value:
                lines.append(f"        {line}")
        else:
            lines.append(f"    {label}: {value}")
    return lines


def _structured_lines(value: Any, indent: int) -> list[str]:
    """An extension value as indented lines: mappings as ``key: value``, lists item by item."""

    indent_str = " " * 4 * indent
    if value is None:
        return []
    lines: list[str] = []
    if isinstance(value, Mapping):
        for key, val in value.items():
            if val in (None, ""):
                continue
            if isinstance(val, (Mapping, list, tuple)):
                lines.append(f"{indent_str}{key}:")
                lines.extend(_structured_lines(val, indent + 1))
            else:
                lines.append(f"{indent_str}{key}: {val}")
        return lines
    if isinstance(value, (list, tuple)):
        if all(isinstance(item, str) for item in value):
            for item in value:
                if item:
                    lines.append(f"{indent_str}{item}")
        else:
            for item in value:
                lines.extend(_structured_lines(item, indent))
        return lines
    return [f"{indent_str}{value}"]


def _extension_header(ext_info: Mapping[str, Any]) -> str:
    oid = ext_info.get("oid")
    friendly = ext_info.get("friendlyName")
    name = ext_info.get("name")
    include_oid = ext_info.get("includeOidInHeader", True)
    header_override = ext_info.get("displayHeader")

    if isinstance(header_override, str) and header_override.strip():
        header = header_override.strip()
    else:
        header_parts: list[str] = []
        if include_oid and oid:
            header_parts.append(oid)
        display_name = friendly or (name if name and name != oid else None)
        if display_name:
            if include_oid and header_parts:
                header_parts.append(f"({display_name})")
            else:
                header_parts.append(display_name)
        if not header_parts:
            fallback = name or friendly or oid or "Extension"
            header_parts.append(fallback)
        header = " ".join(header_parts)

    if ext_info.get("critical"):
        header = f"{header} [critical]"
    return header


def _extensions_section(extensions: Sequence[Mapping[str, Any]]) -> list[str]:
    if not extensions:
        return []
    lines = ["X509v3 extensions:"]
    for ext_info in extensions:
        lines.append(f"    {_extension_header(ext_info)}:")
        lines.extend(_structured_lines(ext_info.get("value"), 2))
    return lines


def _signature_section(signature_algorithm: str, signature_lines: Sequence[str]) -> list[str]:
    if not signature_lines:
        return []
    return [f"Signature Algorithm: {signature_algorithm}", *(f"    {line}" for line in signature_lines)]


def _fingerprint_section(fingerprints: Mapping[str, str]) -> list[str]:
    fingerprint_order = ["md5", "sha1", "sha256"]
    if not any(fingerprints.get(label) for label in fingerprint_order):
        return []
    lines = ["Fingerprint:"]
    for label in fingerprint_order:
        hex_value = fingerprints.get(label)
        if not hex_value:
            continue
        colon_lines = formatting.format_hex_string_lines(hex_value)
        lines.append(f"    {label.upper()}:")
        for line in colon_lines:
            lines.append(f"        {line}")
    return lines


def _subject_key_identifier_section(certificate: Any) -> list[str]:
    try:
        ski_extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
    except x509.ExtensionNotFound:
        return []
    ski_lines = formatting.format_hex_bytes_lines(ski_extension.value.digest)
    if not ski_lines:
        return []
    return ["Subject Key Identifier:", *(f"    {line}" for line in ski_lines)]


def _build_certificate_summary(
    certificate: Any,
    *,
    version_number: int,
    version_hex: str,
    serial_decimal: str,
    serial_hex: str,
    signature_algorithm: str,
    not_valid_before: datetime,
    not_valid_after: datetime,
    public_key: Any,
    fallback_public_key_summary: Sequence[tuple[str, Any]],
    extensions: Sequence[Mapping[str, Any]],
    signature_lines: Sequence[str],
    fingerprints: Mapping[str, str],
) -> str:
    sections = [
        [
            f"Version: {version_number} ({version_hex})",
            f"Certificate Serial Number: {serial_decimal} ({serial_hex})",
            f"Signature Algorithm: {signature_algorithm}",
            f"Issuer: {certificate_names.format_x509_name(certificate.issuer)}",
        ],
        [
            "Validity:",
            f"    Not Before: {_isoformat(not_valid_before)}",
            f"    Not After: {_isoformat(not_valid_after)}",
        ],
        [f"Subject: {certificate_names.format_x509_name(certificate.subject)}"],
        _public_key_section(_public_key_entries(public_key, fallback_public_key_summary)),
        _extensions_section(extensions),
        _signature_section(signature_algorithm, signature_lines),
        _fingerprint_section(fingerprints),
        _subject_key_identifier_section(certificate),
    ]

    summary_lines: list[str] = []
    for section in sections:
        if not section:
            continue
        # One blank line between sections; no section line is itself blank.
        if summary_lines and summary_lines[-1] != "":
            summary_lines.append("")
        summary_lines.extend(section)
    return "\n".join(line for line in summary_lines if line is not None).strip()
