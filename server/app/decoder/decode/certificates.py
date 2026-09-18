"""Certificate summary and key/fingerprint rendering helpers."""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from ... import encoding
from ...attestation import format_hex_bytes_lines, format_hex_string_lines
from ...encoding import encode_base64


def _format_certificate_time(value: Any) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        normalized = text.replace("Z", "+00:00")
        try:
            timestamp = datetime.fromisoformat(normalized)
        except ValueError:
            return text
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        return timestamp.isoformat()
    return None


def _build_subject_public_key_info_lines(info: Any) -> list[str]:
    if not isinstance(info, Mapping):
        return []

    lines: list[str] = ["Subject Public Key Info:"]

    key_type = info.get("type")
    if key_type:
        lines.append(f"Type: {key_type}")

    key_size = info.get("keySize")
    if isinstance(key_size, int):
        lines.append(f"Public-Key: ({key_size} bit)")

    point_lines = _format_public_key_point_lines(info.get("uncompressedPoint"))
    if point_lines:
        lines.append("pub:")
        lines.extend(point_lines)

    curve = info.get("curve")
    if not curve and isinstance(info.get("algorithm"), Mapping):
        curve = info["algorithm"].get("namedCurve")
    if curve:
        lines.append(f"Curve: {curve}")

    return [line for line in lines if line]


def _format_public_key_point_lines(point: Any) -> list[str]:
    if isinstance(point, str) and point.strip():
        return format_hex_string_lines(point)
    return []


def _build_signature_lines(signature: Any) -> list[str]:
    if not isinstance(signature, Mapping):
        return []

    lines: list[str] = []
    algorithm = signature.get("algorithm")
    if algorithm:
        lines.append(f"Signature Algorithm: {algorithm}")

    hex_lines: list[str]
    signature_lines = signature.get("lines")
    if isinstance(signature_lines, list) and signature_lines:
        hex_lines = [line for line in signature_lines if line]
    else:
        hex_value = signature.get("hex")
        if isinstance(hex_value, str) and hex_value.strip():
            hex_lines = format_hex_string_lines(hex_value)
        else:
            hex_lines = []

    lines.extend(hex_lines)
    return lines


def _build_fingerprint_lines(fingerprints: Any) -> list[str]:
    if not isinstance(fingerprints, Mapping):
        return []

    ordered: list[tuple[str, list[str]]] = []
    for label in ("md5", "sha1", "sha256"):
        value = fingerprints.get(label)
        if isinstance(value, str) and value.strip():
            ordered.append((label.upper(), format_hex_string_lines(value)))

    if not ordered:
        return []

    lines: list[str] = ["Fingerprint:"]
    for name, hex_lines in ordered:
        lines.append(f"{name}:")
        lines.extend(hex_lines)
    return lines


def _build_subject_key_identifier_lines(decoded: Mapping[str, Any]) -> list[str]:
    extensions = decoded.get("extensions") if isinstance(decoded, Mapping) else None
    if isinstance(extensions, list):
        for extension in extensions:
            if not isinstance(extension, Mapping):
                continue
            oid = str(extension.get("oid") or "")
            if oid == "2.5.29.14":
                value = extension.get("value")
                if isinstance(value, Mapping):
                    for key in ("Subject Key Identifier", "subjectKeyIdentifier", "value"):
                        digest = value.get(key)
                        if isinstance(digest, str) and digest.strip():
                            return format_hex_string_lines(digest)
                raw_bytes = extension.get("bytes")
                if isinstance(raw_bytes, (bytes, bytearray)):
                    return format_hex_bytes_lines(bytes(raw_bytes))

    if isinstance(decoded, Mapping):
        der_b64 = decoded.get("derBase64")
        if isinstance(der_b64, str) and der_b64.strip():
            der_bytes = encoding.try_decode_base64(der_b64)
            if der_bytes:
                try:
                    certificate = x509.load_der_x509_certificate(der_bytes)
                except Exception:
                    certificate = None
                if certificate is not None:
                    try:
                        ski_extension = certificate.extensions.get_extension_for_oid(
                            ExtensionOID.SUBJECT_KEY_IDENTIFIER
                        )
                    except x509.ExtensionNotFound:
                        try:
                            derived = x509.SubjectKeyIdentifier.from_public_key(
                                certificate.public_key()
                            )
                        except Exception:
                            digest_bytes = None
                        else:
                            digest_bytes = derived.digest
                    else:
                        digest_bytes = ski_extension.value.digest
                    if digest_bytes:
                        return format_hex_bytes_lines(digest_bytes)

    public_key_info = decoded.get("publicKeyInfo") if isinstance(decoded, Mapping) else None
    if isinstance(public_key_info, Mapping):
        spki_b64 = public_key_info.get("subjectPublicKeyInfoBase64")
        if isinstance(spki_b64, str) and spki_b64.strip():
            spki_bytes = encoding.try_decode_base64(spki_b64)
            if spki_bytes is not None:
                digest = hashlib.sha1(spki_bytes).digest()
                return format_hex_bytes_lines(digest)

    return []


_DEVICE_IDENTIFIER_NAMES: dict[str, str] = {
    "1.3.6.1.4.1.41482.1.1": "Security Key by Yubico Series",
}


def _build_certificate_extensions_lines(extensions: Any) -> list[str]:
    if not isinstance(extensions, list) or not extensions:
        return []

    lines: list[str] = ["X509v3 extensions:"]
    for extension in extensions:
        if not isinstance(extension, Mapping):
            continue
        header = _format_certificate_extension_header(extension)
        if header:
            lines.append(f"{header}:")
        value_lines = _format_certificate_extension_value(extension.get("value"))
        lines.extend(value_lines)
    return lines


def _format_certificate_extension_header(extension: Mapping[str, Any]) -> str | None:
    display_header = extension.get("displayHeader")
    if isinstance(display_header, str) and display_header.strip():
        return display_header.strip()

    include_oid = extension.get("includeOidInHeader", True)
    oid = extension.get("oid")
    friendly = extension.get("friendlyName") or extension.get("name")

    parts: list[str] = []
    if include_oid and oid:
        parts.append(str(oid))
    if friendly and friendly != oid:
        friendly_part = f"({friendly})" if include_oid and parts else str(friendly)
        parts.append(friendly_part)

    if not parts:
        if oid:
            parts.append(str(oid))
        elif friendly:
            parts.append(str(friendly))
        else:
            return None

    return " ".join(parts)


def _format_certificate_extension_value(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, Mapping):
        lines: list[str] = []
        hex_value = None
        device_identifier = None

        for key, entry in value.items():
            if entry in (None, ""):
                continue
            key_lower = str(key).lower()
            if key_lower == "hex value":
                hex_value = str(entry)
            elif key_lower == "device identifier":
                device_identifier = entry
            elif isinstance(entry, (Mapping, list, tuple)):
                lines.append(f"{key}:")
                lines.extend(_format_certificate_extension_value(entry))
            else:
                lines.append(f"{key}: {entry}")

        ordered: list[str] = []
        if hex_value is not None:
            ordered.append(f"Hex value: {hex_value}")
        if device_identifier is not None:
            ordered.append(_format_device_identifier_line(device_identifier))
        ordered.extend(lines)
        return ordered

    if isinstance(value, (list, tuple)):
        lines: list[str] = []
        for item in value:
            if item in (None, ""):
                continue
            if isinstance(item, (Mapping, list, tuple)):
                lines.extend(_format_certificate_extension_value(item))
            else:
                lines.append(str(item))
        return lines

    return [str(value)]


def _format_device_identifier_line(identifier: Any) -> str:
    if not isinstance(identifier, str):
        return str(identifier)
    cleaned = identifier.strip()
    friendly = _DEVICE_IDENTIFIER_NAMES.get(cleaned)
    return f"{cleaned} ({friendly})" if friendly else cleaned


def _convert_certificate_payload_impl(
    entry: Mapping[str, Any], cert_bytes: bytes | None = None
) -> dict[str, Any]:
    if not isinstance(entry, Mapping):
        return {}

    payload: dict[str, Any] = {}

    if cert_bytes is None:
        der_base64 = entry.get("derBase64")
        if isinstance(der_base64, str):
            cert_bytes = encoding.try_decode_base64(der_base64)

    if cert_bytes is not None:
        payload["raw"] = cert_bytes.hex()

    pem_value = entry.get("pem")
    if isinstance(pem_value, str) and pem_value.strip():
        payload["pem"] = pem_value

    parsed_entry = {key: value for key, value in entry.items() if key != "summary"}
    payload["parsedX5c"] = parsed_entry

    return payload


def _convert_certificate_bytes_impl(
    value: Any,
    *,
    serializer: Callable[[bytes], Any],
    convert_certificate_payload: Callable[[Mapping[str, Any], bytes | None], dict[str, Any]],
) -> dict[str, Any]:
    cert_bytes: bytes | None = None
    if isinstance(value, (bytes, bytearray)):
        cert_bytes = bytes(value)
    elif isinstance(value, str):
        cert_bytes = encoding.try_decode_base64(value)
    elif isinstance(value, Mapping):
        return convert_certificate_payload(value, cert_bytes)

    if cert_bytes is None:
        return {}

    parsed = serializer(cert_bytes)
    if not isinstance(parsed, Mapping):
        return {}

    parsed_copy = dict(parsed)
    parsed_copy["derBase64"] = parsed.get("derBase64") or encode_base64(cert_bytes)
    parsed_copy.setdefault("pem", parsed.get("pem"))
    return convert_certificate_payload(parsed_copy, cert_bytes)


def _convert_certificate_chain_impl(
    value: Any,
    *,
    convert_certificate_bytes: Callable[[Any], dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    certificates: list[dict[str, Any]] = []
    for item in value:
        cert_payload = convert_certificate_bytes(item)
        if cert_payload:
            certificates.append(cert_payload)
    return certificates


def _convert_attestation_statement_impl(
    details: Any,
    *,
    convert_certificate_chain: Callable[[Any], list[dict[str, Any]]],
) -> dict[str, Any]:
    if not isinstance(details, Mapping):
        return {}

    statement = details.get("attestationStatement") if isinstance(details.get("attestationStatement"), Mapping) else None
    if statement is None:
        cbor_section = details.get("cbor") if isinstance(details.get("cbor"), Mapping) else None
        if isinstance(cbor_section, Mapping):
            possible = cbor_section.get("attStmt")
            if isinstance(possible, Mapping):
                statement = possible

    if not isinstance(statement, Mapping):
        return {}

    payload: dict[str, Any] = {}
    for key, value in statement.items():
        if key == "x5c":
            payload["x5c"] = convert_certificate_chain(value)
        else:
            payload[key] = value
    return payload


def _convert_attestation_entry_impl(
    entry: Any,
    *,
    convert_attestation_statement: Callable[[Any], dict[str, Any]],
    convert_certificate_payload: Callable[[Mapping[str, Any], bytes | None], dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(entry, Mapping):
        return {}

    details = entry.get("details") if isinstance(entry.get("details"), Mapping) else entry
    payload: dict[str, Any] = {}

    fmt = None
    if isinstance(details, Mapping):
        fmt = details.get("attestationFormat") or details.get("fmt")
        cbor_section = details.get("cbor") if isinstance(details.get("cbor"), Mapping) else None
        if fmt is None and isinstance(cbor_section, Mapping):
            fmt = cbor_section.get("fmt")
    if fmt:
        payload["fmt"] = fmt

    raw_value = entry.get("raw")
    if isinstance(raw_value, str) and raw_value:
        payload["raw"] = raw_value

    att_stmt = convert_attestation_statement(details)
    if att_stmt:
        if "x5c" in att_stmt and not att_stmt["x5c"]:
            certificate_detail = None
            if isinstance(details, Mapping):
                certificate_detail = details.get("attestationCertificate")
                if certificate_detail is None:
                    certificates_list = details.get("attestationCertificates")
                    if isinstance(certificates_list, list) and certificates_list:
                        certificate_detail = certificates_list[0]
            if certificate_detail is not None:
                converted = convert_certificate_payload(certificate_detail, None)
                if converted:
                    att_stmt["x5c"] = [converted]
        payload["attStmt"] = att_stmt

    return payload
