"""What a registration's request expected: whether user verification is required, which algorithms it allowed, and its challenge."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ... import encoding


def resolve_uv_required(
    state: Mapping[str, Any] | None,
    public_key_options: Mapping[str, Any] | None,
) -> bool:
    uv_required = False
    if isinstance(state, Mapping):
        state_uv = state.get("user_verification")
        if getattr(state_uv, "value", None) == "required" or state_uv == "required":
            uv_required = True

    if not uv_required and isinstance(public_key_options, Mapping):
        uv_setting: str | None = None
        authenticator_selection = public_key_options.get("authenticatorSelection")
        if isinstance(authenticator_selection, Mapping):
            uv_setting = authenticator_selection.get("userVerification")
        if not uv_setting:
            uv_setting = public_key_options.get("userVerification")
        if isinstance(uv_setting, str) and uv_setting.lower() == "required":
            uv_required = True

    return uv_required


def collect_allowed_algorithms(
    public_key_options: Mapping[str, Any] | None,
) -> list[int]:
    allowed_algorithms: list[int] = []
    if isinstance(public_key_options, Mapping):
        params = public_key_options.get("pubKeyCredParams")
        if isinstance(params, list):
            for param in params:
                if isinstance(param, Mapping) and isinstance(param.get("alg"), int):
                    allowed_algorithms.append(param["alg"])
    return allowed_algorithms


def _coerce_expected_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        for decoder in (
            encoding.try_decode_base64url,
            encoding.try_decode_base64,
            encoding.try_decode_hex,
        ):
            decoded = decoder(value)
            if decoded is not None:
                return decoded
        return value.encode("utf-8")
    if isinstance(value, Mapping):
        if "$base64url" in value:
            return _coerce_expected_bytes(value["$base64url"])
        if "$base64" in value:
            encoded = value["$base64"]
            if not isinstance(encoded, str):
                return b""
            return encoding.try_decode_base64(encoded) or b""
        if "$hex" in value:
            hex_value = value["$hex"]
            if not isinstance(hex_value, str):
                return b""
            return encoding.try_decode_hex(hex_value) or b""
    return b""


def resolve_expected_challenge(
    state: Mapping[str, Any] | None,
    public_key_options: Mapping[str, Any] | None,
) -> bytes:
    expected_challenge_bytes = b""
    if isinstance(state, Mapping):
        expected_challenge_bytes = _coerce_expected_bytes(state.get("challenge"))
    if not expected_challenge_bytes and isinstance(public_key_options, Mapping):
        expected_challenge_bytes = _coerce_expected_bytes(
            public_key_options.get("challenge")
        )
    return expected_challenge_bytes
