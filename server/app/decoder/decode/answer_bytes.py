"""Bytes the decoder answer reads back from a reading's entries: a field's hex or
base64url, and the authenticator data a response or its attestation object holds."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ... import encoding
from . import cbor_parser


def _extract_hex_from_binary(entry: Mapping[str, Any]) -> str | None:
    direct_hex = entry.get("hex")
    if isinstance(direct_hex, str) and direct_hex:
        return direct_hex
    binary = entry.get("binary")
    if isinstance(binary, Mapping):
        hex_value = binary.get("hex")
        if isinstance(hex_value, str) and hex_value:
            return hex_value
    return None


def extract_bytes_from_binary(entry: Any) -> bytes | None:
    if not isinstance(entry, Mapping):
        return None
    hex_value = _extract_hex_from_binary(entry)
    if isinstance(hex_value, str):
        decoded = encoding.try_decode_hex(hex_value)
        if decoded is not None:
            return decoded

    raw_value = entry.get("raw")
    if isinstance(raw_value, str) and raw_value:
        return encoding.try_decode_base64url(raw_value)

    return None


def extract_authenticator_bytes(response: Any, attestation_entry: Any = None) -> bytes | None:
    if isinstance(response, Mapping):
        auth_entry = response.get("authenticatorData")
        auth_bytes = extract_bytes_from_binary(auth_entry)
        if auth_bytes is not None:
            return auth_bytes
        if attestation_entry is None:
            attestation_entry = response.get("attestationObject")
    return extract_authenticator_bytes_from_attestation(attestation_entry)


def extract_authenticator_bytes_from_attestation(attestation_entry: Any) -> bytes | None:
    attestation_bytes = extract_bytes_from_binary(attestation_entry)
    if attestation_bytes is None and isinstance(attestation_entry, Mapping):
        raw_value = attestation_entry.get("raw")
        if isinstance(raw_value, str) and raw_value:
            attestation_bytes = encoding.try_decode_base64(raw_value)

    if attestation_bytes is None:
        return None

    try:
        node, _, _ = cbor_parser.decode_item(attestation_bytes)
    except ValueError:
        return None
    attestation = cbor_parser._structure_to_value(node)
    auth_data = attestation.get("authData") if isinstance(attestation, Mapping) else None
    return auth_data if isinstance(auth_data, bytes) else None
