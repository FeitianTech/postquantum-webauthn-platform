"""Binary/COSE/authenticator extraction utilities for decoder internals."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fido2.webauthn import AttestationObject

from ... import encoding
from ...webauthn import pqc


def _resolve_cose_algorithm(public_key: Any, fallback: Any | None = None) -> str | None:
    alg_value: Any | None = None
    if isinstance(public_key, Mapping):
        if 3 in public_key:
            alg_value = public_key[3]
        elif "3" in public_key:
            alg_value = public_key["3"]
        elif "alg" in public_key:
            alg_value = public_key["alg"]

    if alg_value is None:
        if isinstance(fallback, Mapping):
            alg_value = fallback.get("publicKeyAlgorithm")
        elif isinstance(fallback, int):
            alg_value = fallback

    if alg_value is None:
        return None

    try:
        alg_int = int(alg_value)
    except (TypeError, ValueError):
        return str(alg_value)
    return pqc.describe_algorithm(alg_int)


def _convert_cose_key_for_display(public_key: Any) -> Any:
    if isinstance(public_key, Mapping):
        return {key: _convert_cose_key_for_display(value) for key, value in public_key.items()}
    if isinstance(public_key, list):
        return [_convert_cose_key_for_display(item) for item in public_key]
    if isinstance(public_key, str):
        decoded = _decode_base64_field(public_key)
        if decoded is not None:
            return decoded.hex()
    return public_key


def _decode_base64_field(value: str) -> bytes | None:
    """Decode a COSE display field that may be base64 or base64url.

    The round-trip check the open-coded version needed is gone: strict
    decoding already refuses anything that would not re-encode to the input.
    """

    cleaned = value.strip()
    if not cleaned:
        return None
    decoded = encoding.try_decode_base64url(cleaned)
    if decoded is None:
        decoded = encoding.try_decode_base64(cleaned)
    return decoded


def _extract_hex_from_binary(entry: Any) -> str | None:
    if not isinstance(entry, Mapping):
        return None
    direct_hex = entry.get("hex")
    if isinstance(direct_hex, str) and direct_hex:
        return direct_hex
    binary = entry.get("binary")
    if isinstance(binary, Mapping):
        hex_value = binary.get("hex")
        if isinstance(hex_value, str) and hex_value:
            return hex_value
    return None


def _extract_bytes_from_binary(entry: Any) -> bytes | None:
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


def _extract_authenticator_bytes(response: Any, attestation_entry: Any = None) -> bytes | None:
    if isinstance(response, Mapping):
        auth_entry = response.get("authenticatorData")
        auth_bytes = _extract_bytes_from_binary(auth_entry)
        if auth_bytes is not None:
            return auth_bytes
        if attestation_entry is None:
            attestation_entry = response.get("attestationObject")
    return _extract_authenticator_bytes_from_attestation(attestation_entry)


def _extract_authenticator_bytes_from_attestation(attestation_entry: Any) -> bytes | None:
    attestation_bytes = _extract_bytes_from_binary(attestation_entry)
    if attestation_bytes is None and isinstance(attestation_entry, Mapping):
        raw_value = attestation_entry.get("raw")
        if isinstance(raw_value, str) and raw_value:
            attestation_bytes = encoding.try_decode_base64(raw_value)

    if attestation_bytes is None:
        return None

    try:
        attestation = AttestationObject(attestation_bytes)
    except Exception:
        return None

    try:
        return bytes(attestation.auth_data)
    except Exception:
        return None
