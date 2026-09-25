"""Authenticator data inside a CTAP view: its fields as far as its flags describe them, and its raw bytes."""
from __future__ import annotations

from typing import Any

from fido2.webauthn import AuthenticatorData

from . import cbor_parser
from .cbor_parser import _CborDecodingError, _structure_to_value
from .keys import hex_json_safe as _hex_json_safe


def _parse_authenticator_data_bytes(data: bytes) -> tuple[dict[str, Any], bytes, bytes]:
    """Read authenticator data as far as its flags describe it.

    Returns the details, the bytes the flags account for, and any bytes after
    them. The credential public key and the extensions are read with the strict
    parser; one that is not well-formed is shown as hex with a ``parseError``
    saying where, never completed or skipped.
    """

    details: dict[str, Any] = {}
    if len(data) < 37:
        details["parseError"] = "Authenticator data shorter than minimum header."
        return details, data, b""

    rp_id_hash = data[:32]
    flags_byte = data[32]
    sign_count = int.from_bytes(data[33:37], "big")
    offset = 37

    details["rpIdHash"] = rp_id_hash.hex()
    details["flags"] = {
        "value": flags_byte,
        "bitfield": f"0b{flags_byte:08b}",
        "UP": bool(flags_byte & AuthenticatorData.FLAG.UP),
        "UV": bool(flags_byte & AuthenticatorData.FLAG.UV),
        "BE": bool(flags_byte & AuthenticatorData.FLAG.BE),
        "BS": bool(flags_byte & AuthenticatorData.FLAG.BS),
        "AT": bool(flags_byte & AuthenticatorData.FLAG.AT),
        "ED": bool(flags_byte & AuthenticatorData.FLAG.ED),
    }
    details["signCount"] = sign_count

    if flags_byte & AuthenticatorData.FLAG.AT:
        attested: dict[str, Any] = {}
        details["attestedCredentialData"] = attested
        remaining = len(data) - offset
        if remaining < 18:
            attested["parseError"] = (
                f"Attested credential data truncated: it needs at least 18 bytes, {remaining} remain."
            )
            offset = len(data)
        else:
            aaguid = data[offset : offset + 16]
            declared_len = int.from_bytes(data[offset + 16 : offset + 18], "big")
            offset += 18
            actual_len = min(declared_len, len(data) - offset)
            credential_id = data[offset : offset + actual_len]
            offset += actual_len

            attested["aaguid"] = aaguid.hex()
            attested["credentialIdDeclaredLength"] = declared_len
            attested["credentialIdActualLength"] = actual_len
            attested["credentialId"] = credential_id.hex()
            if actual_len != declared_len:
                attested["lengthMismatch"] = True
                attested["parseError"] = (
                    f"The credential ID declares {declared_len} bytes; {actual_len} remain."
                )
            elif offset < len(data):
                offset = _read_embedded_cbor(data, offset, attested, "credentialPublicKey")

    if flags_byte & AuthenticatorData.FLAG.ED and offset < len(data):
        offset = _read_embedded_cbor(data, offset, details, "extensions")

    return details, data[:offset], data[offset:]


def _read_embedded_cbor(data: bytes, offset: int, target: dict[str, Any], field: str) -> int:
    try:
        node, end, _ = cbor_parser.decode_item(data, offset)
    except _CborDecodingError as exc:
        target[field] = data[offset:].hex()
        target["parseError"] = (
            f"{field} is not well-formed CBOR at authData offset {exc.offset}: {exc.reason}"
        )
        return len(data)
    target[field] = _hex_json_safe(_structure_to_value(node))
    return end


def _format_auth_data_for_expanded_json(auth_data_bytes: bytes) -> tuple[dict[str, Any], bytes]:
    details, trimmed, trailing = _parse_authenticator_data_bytes(auth_data_bytes)
    formatted: dict[str, Any] = dict(details)
    formatted.setdefault("raw", trimmed.hex())
    if trailing:
        formatted["trailingBytesHex"] = trailing.hex()
    return formatted, trailing
