"""Implementation helpers for certificate/attestation conversion wrappers."""
from __future__ import annotations

import base64
import binascii
from typing import Any, Callable, Dict, List, Mapping, Optional


def _convert_certificate_payload_impl(
    entry: Mapping[str, Any], cert_bytes: Optional[bytes] = None
) -> Dict[str, Any]:
    if not isinstance(entry, Mapping):
        return {}

    payload: Dict[str, Any] = {}

    if cert_bytes is None:
        der_base64 = entry.get("derBase64")
        if isinstance(der_base64, str):
            try:
                cert_bytes = base64.b64decode(der_base64)
            except (ValueError, binascii.Error):
                cert_bytes = None

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
    convert_certificate_payload: Callable[[Mapping[str, Any], Optional[bytes]], Dict[str, Any]],
) -> Dict[str, Any]:
    cert_bytes: Optional[bytes] = None
    if isinstance(value, (bytes, bytearray)):
        cert_bytes = bytes(value)
    elif isinstance(value, str):
        cleaned = "".join(value.split())
        padding = (-len(cleaned)) % 4
        try:
            cert_bytes = base64.b64decode(cleaned + "=" * padding)
        except (ValueError, binascii.Error):
            cert_bytes = None
    elif isinstance(value, Mapping):
        return convert_certificate_payload(value, cert_bytes)

    if cert_bytes is None:
        return {}

    parsed = serializer(cert_bytes)
    if not isinstance(parsed, Mapping):
        return {}

    parsed_copy = dict(parsed)
    parsed_copy["derBase64"] = parsed.get("derBase64") or base64.b64encode(cert_bytes).decode("ascii")
    parsed_copy.setdefault("pem", parsed.get("pem"))
    return convert_certificate_payload(parsed_copy, cert_bytes)


def _convert_certificate_chain_impl(
    value: Any,
    *,
    convert_certificate_bytes: Callable[[Any], Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []

    certificates: List[Dict[str, Any]] = []
    for item in value:
        cert_payload = convert_certificate_bytes(item)
        if cert_payload:
            certificates.append(cert_payload)
    return certificates


def _convert_attestation_statement_impl(
    details: Any,
    *,
    convert_certificate_chain: Callable[[Any], List[Dict[str, Any]]],
) -> Dict[str, Any]:
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

    payload: Dict[str, Any] = {}
    for key, value in statement.items():
        if key == "x5c":
            payload["x5c"] = convert_certificate_chain(value)
        else:
            payload[key] = value
    return payload


def _convert_attestation_entry_impl(
    entry: Any,
    *,
    convert_attestation_statement: Callable[[Any], Dict[str, Any]],
    convert_certificate_payload: Callable[[Mapping[str, Any], Optional[bytes]], Dict[str, Any]],
) -> Dict[str, Any]:
    if not isinstance(entry, Mapping):
        return {}

    details = entry.get("details") if isinstance(entry.get("details"), Mapping) else entry
    payload: Dict[str, Any] = {}

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
