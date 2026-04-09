from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Sequence, Tuple


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
    fallback_public_key_summary: Sequence[Tuple[str, Any]],
    extensions: Sequence[Mapping[str, Any]],
    signature_lines: Sequence[str],
    fingerprints: Mapping[str, str],
) -> str:
    summary_lines: List[str] = []

    def _append_line(line: str) -> None:
        summary_lines.append(line)

    def _append_blank_line() -> None:
        if summary_lines and summary_lines[-1] != "":
            summary_lines.append("")

    def _isoformat(value: datetime) -> str:
        return _ensure_utc_datetime(value).isoformat()

    _append_line(f"Version: {version_number} ({version_hex})")
    _append_line(
        f"Certificate Serial Number: {serial_decimal} ({serial_hex})"
    )
    _append_line(f"Signature Algorithm: {signature_algorithm}")
    _append_line(f"Issuer: {format_x509_name(certificate.issuer)}")

    _append_blank_line()
    _append_line("Validity:")
    _append_line(f"    Not Before: {_isoformat(not_valid_before)}")
    _append_line(f"    Not After: {_isoformat(not_valid_after)}")

    _append_blank_line()
    _append_line(f"Subject: {format_x509_name(certificate.subject)}")

    pk_summary_entries: List[Tuple[str, Any]] = []
    if public_key is None:
        pk_summary_entries.extend(fallback_public_key_summary)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        pk_summary_entries.append(("Type", "ECC"))
        if public_key.key_size:
            pk_summary_entries.append(("Public-Key", f"({public_key.key_size} bit)"))
        ecc_point_lines = format_hex_bytes_lines(
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
        modulus_lines = format_hex_bytes_lines(modulus_bytes)
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
        raw_lines = format_hex_bytes_lines(raw_bytes)
        if raw_lines:
            pk_summary_entries.append(("Public Key", raw_lines))
    else:
        pk_summary_entries.append(("Type", public_key.__class__.__name__))

    if pk_summary_entries:
        _append_blank_line()
        _append_line("Subject Public Key Info:")
        for label, value in pk_summary_entries:
            if value is None or (isinstance(value, list) and not value):
                continue
            if isinstance(value, list):
                _append_line(f"    {label}:")
                for line in value:
                    _append_line(f"        {line}")
            else:
                _append_line(f"    {label}: {value}")

    if extensions:
        _append_blank_line()
        _append_line("X509v3 extensions:")

        def _append_structured(value: Any, indent: int) -> None:
            indent_str = " " * 4 * indent
            if value is None:
                return
            if isinstance(value, Mapping):
                for key, val in value.items():
                    if val in (None, ""):
                        continue
                    if isinstance(val, (Mapping, list, tuple)):
                        _append_line(f"{indent_str}{key}:")
                        _append_structured(val, indent + 1)
                    else:
                        _append_line(f"{indent_str}{key}: {val}")
                return
            if isinstance(value, (list, tuple)):
                if all(isinstance(item, str) for item in value):
                    for item in value:
                        if item:
                            _append_line(f"{indent_str}{item}")
                else:
                    for item in value:
                        _append_structured(item, indent)
                return
            _append_line(f"{indent_str}{value}")

        for ext_info in extensions:
            oid = ext_info.get("oid")
            friendly = ext_info.get("friendlyName")
            name = ext_info.get("name")
            include_oid = ext_info.get("includeOidInHeader", True)
            header_override = ext_info.get("displayHeader")

            if isinstance(header_override, str) and header_override.strip():
                header = header_override.strip()
            else:
                header_parts: List[str] = []
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
            _append_line(f"    {header}:")
            _append_structured(ext_info.get("value"), 2)

    if signature_lines:
        _append_blank_line()
        _append_line(f"Signature Algorithm: {signature_algorithm}")
        for line in signature_lines:
            _append_line(f"    {line}")

    fingerprint_order = ["md5", "sha1", "sha256"]
    if any(fingerprints.get(label) for label in fingerprint_order):
        _append_blank_line()
        _append_line("Fingerprint:")
        for label in fingerprint_order:
            hex_value = fingerprints.get(label)
            if not hex_value:
                continue
            colon_lines = format_hex_string_lines(hex_value)
            _append_line(f"    {label.upper()}:")
            for line in colon_lines:
                _append_line(f"        {line}")

    try:
        ski_extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
    except x509.ExtensionNotFound:
        ski_lines: List[str] = []
    else:
        ski_lines = format_hex_bytes_lines(ski_extension.value.digest)

    if ski_lines:
        _append_blank_line()
        _append_line("Subject Key Identifier:")
        for line in ski_lines:
            _append_line(f"    {line}")

    return "\n".join(line for line in summary_lines if line is not None).strip()
