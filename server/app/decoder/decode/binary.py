"""Binary/COSE/authenticator extraction utilities for decoder internals."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ... import encoding
from ...webauthn import mldsa, pqc
from .. import cose_tables

# One registry, shared with the encoder.
_COSE_KEY_TYPES = cose_tables.KEY_TYPES
_COSE_CURVES = cose_tables.CURVES


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
            expected = mldsa.parameter_details(parameter_set).get("public_key_length")
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
