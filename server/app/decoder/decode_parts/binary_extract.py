"""Binary/COSE/authenticator extraction utilities for decoder internals."""
from __future__ import annotations

import base64
import binascii
from typing import Any, Dict, Mapping, Optional

from fido2.webauthn import AttestationObject

_COSE_ALG_LABELS: Dict[int, str] = {
    -8: "EdDSA",
    -7: "ES256",
    -35: "ES256K",
    -36: "ES384",
    -37: "ES512",
    -257: "RS256",
    -258: "RS384",
    -259: "RS512",
}


def _resolve_cose_algorithm(public_key: Any, fallback: Optional[Any] = None) -> Optional[str]:
    alg_value: Optional[Any] = None
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
    return _COSE_ALG_LABELS.get(alg_int, str(alg_int))


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


def _decode_base64_field(value: str) -> Optional[bytes]:
    cleaned = value.strip()
    if not cleaned:
        return None
    normalized = cleaned.replace('-', '+').replace('_', '/')
    padding = (-len(normalized)) % 4
    try:
        decoded = base64.b64decode(normalized + '=' * padding)
    except (ValueError, binascii.Error):
        return None

    if base64.urlsafe_b64encode(decoded).rstrip(b'=') == cleaned.encode('ascii').rstrip(b'='):
        return decoded
    if base64.b64encode(decoded).rstrip(b'=') == normalized.encode('ascii').rstrip(b'='):
        return decoded
    return None


def _extract_hex_from_binary(entry: Any) -> Optional[str]:
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


def _extract_bytes_from_binary(entry: Any) -> Optional[bytes]:
    if not isinstance(entry, Mapping):
        return None
    hex_value = _extract_hex_from_binary(entry)
    if isinstance(hex_value, str):
        cleaned = "".join(hex_value.split())
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            pass

    raw_value = entry.get("raw")
    if isinstance(raw_value, str) and raw_value:
        cleaned = "".join(raw_value.split())
        padding = (-len(cleaned)) % 4
        try:
            return base64.urlsafe_b64decode(cleaned + "=" * padding)
        except (ValueError, binascii.Error):
            return None

    return None


def _extract_authenticator_bytes(response: Any, attestation_entry: Any = None) -> Optional[bytes]:
    if isinstance(response, Mapping):
        auth_entry = response.get("authenticatorData")
        auth_bytes = _extract_bytes_from_binary(auth_entry)
        if auth_bytes is not None:
            return auth_bytes
        if attestation_entry is None:
            attestation_entry = response.get("attestationObject")
    return _extract_authenticator_bytes_from_attestation(attestation_entry)


def _extract_authenticator_bytes_from_attestation(attestation_entry: Any) -> Optional[bytes]:
    attestation_bytes = _extract_bytes_from_binary(attestation_entry)
    if attestation_bytes is None and isinstance(attestation_entry, Mapping):
        raw_value = attestation_entry.get("raw")
        if isinstance(raw_value, str) and raw_value:
            cleaned = "".join(raw_value.split())
            padding = (-len(cleaned)) % 4
            try:
                attestation_bytes = base64.b64decode(cleaned + "=" * padding)
            except (ValueError, binascii.Error):
                attestation_bytes = None

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
