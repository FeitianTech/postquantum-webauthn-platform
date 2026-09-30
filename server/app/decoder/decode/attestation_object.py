"""A WebAuthn attestation object (L3 section 6.5.4): read, and read as the decoder's whole input."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ...encoding import try_decode_base64
from ...json_values import make_json_safe
from ...webauthn.attestation import certificates as attestation_certificates
from .. import values
from . import authenticator_data as auth_data_reader
from . import (
    authenticator_data_findings,
    canonical,
    cbor_parser,
    ctap,
    interpretations,
    key_collisions,
)


def read(data: bytes) -> tuple[dict[str, Any], dict[str, Any], int]:
    """Read a WebAuthn attestation object: its details, its CBOR node, where it ends.

    It is a CBOR map with a text ``fmt``, a byte string ``authData`` holding
    valid authenticator data, and a map ``attStmt``; anything else raises.
    """

    node, end, _ = cbor_parser.decode_item(data)
    value = cbor_parser._structure_to_value(node)
    if not isinstance(value, Mapping):
        raise ValueError("An attestation object is a CBOR map.")
    fmt, auth_data, att_stmt = value.get("fmt"), value.get("authData"), value.get("attStmt")
    # WebAuthn L3 section 8.9: a compound statement's attStmt is an array.
    statement = isinstance(att_stmt, Mapping) or (fmt == "compound" and isinstance(att_stmt, list))
    if not isinstance(fmt, str) or not isinstance(auth_data, bytes) or not statement:
        raise ValueError(
            "An attestation object has a text fmt, byte string authData and map attStmt (an array for compound)."
        )

    try:
        authenticator_data = auth_data_reader._describe_authenticator_data_bytes(auth_data)
    except (cbor_parser._CborDecodingError, auth_data_reader._LocatedError) as exc:
        member = authenticator_data_findings.member_node(node, ("authData",))
        start = member["end"] - member["length"] if member and not member.get("indefinite") else 0
        path = member["path"] if member else "$"
        raise type(exc)(exc.reason, start + exc.offset, path + exc.path[1:]) from exc
    details: dict[str, Any] = {
        "attestationFormat": fmt,
        "attestationStatement": make_json_safe(att_stmt),
        "authenticatorData": authenticator_data,
        "cbor": make_json_safe(value),
    }

    certificate_details = extract_certificate(att_stmt)
    if certificate_details is not None:
        details["attestationCertificate"] = certificate_details

    return details, node, end


def extract_certificate(att_stmt: Mapping[str, Any]) -> dict[str, Any] | None:
    if not isinstance(att_stmt, Mapping):
        return None

    chain = att_stmt.get("x5c")
    if not isinstance(chain, Sequence) or not chain:
        return None

    first_entry = chain[0]
    cert_bytes: bytes | None

    if isinstance(first_entry, str):
        cert_bytes = try_decode_base64(first_entry)
    else:
        try:
            cert_bytes = bytes(first_entry)
        except Exception:
            cert_bytes = None

    if not cert_bytes:
        return None

    try:
        return attestation_certificates.serialize_attestation_certificate(cert_bytes)
    except Exception:
        return None


def try_decode(data: bytes, encoding: str) -> dict[str, Any] | None:
    try:
        details, node, end = read(data)
    except Exception:
        return None

    extra, located = interpretations.for_attestation_object(cbor_parser._structure_to_value(node), node, data)
    result: dict[str, Any] = {
        "format": "Attestation object (CBOR)",
        "inputEncoding": encoding,
        "decoded": details,
        "binary": values.binary_summary(data, encoding),
        "extraData": extra,
    }
    structure = canonical.check(node, data) + key_collisions.check(node)
    ctap._attach_findings(result, structure + ctap._trailing_findings(data, end) + located)
    return result
