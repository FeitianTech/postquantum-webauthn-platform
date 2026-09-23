"""Binary/COSE/authenticator extraction utilities for decoder internals."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fido2.cose import _get_mldsa_parameter_details
from fido2.webauthn import AttestationObject

from ... import encoding
from ...webauthn import pqc

# The IANA "COSE Key Types" registry. 7 is AKP, the algorithm key pair type
# ML-DSA keys use: the parameter set comes from alg (3), the key from pub (-1).
_COSE_KEY_TYPES: dict[int, str] = {
    1: "OKP",
    2: "EC2",
    3: "RSA",
    4: "Symmetric",
    5: "HSS-LMS",
    6: "WalnutDSA",
    7: "AKP",
}

# The IANA "COSE Elliptic Curves" registry.
_COSE_CURVES: dict[int, str] = {
    1: "P-256",
    2: "P-384",
    3: "P-521",
    4: "X25519",
    5: "X448",
    6: "Ed25519",
    7: "Ed448",
    8: "secp256k1",
}


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


def _describe_cose_key(public_key: Any) -> dict[str, Any]:
    """Name a COSE key's type and the parameter that sizes it.

    EC2 and OKP keys are sized by their curve, RSA keys by their modulus, and
    AKP (ML-DSA) keys by the parameter set their algorithm names and the length
    of the public key, which is checked against the FIPS 204 size.
    """

    kty = _cose_int_parameter(public_key, 1)
    if kty is None:
        return {}

    details: dict[str, Any] = {"keyType": _registry_label(_COSE_KEY_TYPES, kty, "kty")}
    if kty in (1, 2):
        crv = _cose_int_parameter(public_key, -1)
        if crv is not None:
            details["curve"] = _registry_label(_COSE_CURVES, crv, "crv")
    elif kty == 3:
        modulus = _cose_bytes_parameter(public_key, -1)
        if modulus is not None:
            details["modulusBits"] = int.from_bytes(modulus, "big").bit_length()
    elif kty == 7:
        alg = _cose_int_parameter(public_key, 3)
        parameter_set = pqc.PQC_ALGORITHM_ID_TO_NAME.get(alg) if alg is not None else None
        if parameter_set is not None:
            details["parameterSet"] = parameter_set
        key_bytes = _cose_bytes_parameter(public_key, -1)
        if key_bytes is not None:
            details["publicKeyBytes"] = len(key_bytes)
            expected = _get_mldsa_parameter_details(parameter_set).get("public_key_length")
            if expected is not None and expected != len(key_bytes):
                details["publicKeyBytesExpected"] = expected
    return details


def _registry_label(registry: Mapping[int, str], value: int, parameter: str) -> str:
    name = registry.get(value)
    return f"{name} ({value})" if name is not None else f"COSE {parameter} {value}"


def _cose_parameter(public_key: Any, label: int) -> Any:
    if not isinstance(public_key, Mapping):
        return None
    if label in public_key:
        return public_key[label]
    return public_key.get(str(label))


def _cose_int_parameter(public_key: Any, label: int) -> int | None:
    value = _cose_parameter(public_key, label)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _cose_bytes_parameter(public_key: Any, label: int) -> bytes | None:
    value = _cose_parameter(public_key, label)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return _decode_base64_field(value)
    return None


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
