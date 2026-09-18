"""Advanced-tab binary coercion helpers.

Shared pieces live in :mod:`server.app.routes.binary_helpers`; what stays here
is the advanced tab's own ``{"$hex": ...}``/``{"$base64": ...}`` wrapper
handling, which the simple tab does not have.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ... import encoding
from ..binary_helpers import decode_binary_text


def _decode_wrapped_impl(
    value: Any,
    decoder: Any,
    *,
    error: str = "invalid binary value",
) -> bytes:
    stripped = value.strip()
    if not stripped:
        raise ValueError("empty binary value")
    try:
        return decoder(stripped)
    except encoding.EncodingError as exc:
        raise ValueError(error) from exc


def _decode_client_binary_impl(value: Any) -> bytes:
    if value is None:
        raise ValueError("missing binary value")

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, str):
        if not value.strip():
            raise ValueError("empty binary value")
        try:
            return decode_binary_text(value)
        except encoding.EncodingError as exc:
            raise ValueError("invalid binary value") from exc

    if isinstance(value, Mapping):
        if "$hex" in value or "hex" in value:
            hex_candidate = value.get("$hex")
            if hex_candidate is None:
                hex_candidate = value.get("hex")

            if isinstance(hex_candidate, str):
                return _decode_wrapped_impl(hex_candidate, encoding.decode_hex)

            return _decode_client_binary_impl(hex_candidate)

        if "$base64url" in value or "base64url" in value:
            b64u_candidate = value.get("$base64url")
            if b64u_candidate is None:
                b64u_candidate = value.get("base64url")

            if isinstance(b64u_candidate, str):
                return _decode_wrapped_impl(b64u_candidate, encoding.decode_base64url)

            return _decode_client_binary_impl(b64u_candidate)

        if "$base64" in value or "base64" in value:
            b64_candidate = value.get("$base64")
            if b64_candidate is None:
                b64_candidate = value.get("base64")

            if isinstance(b64_candidate, str):
                return _decode_wrapped_impl(b64_candidate, encoding.decode_base64)

            return _decode_client_binary_impl(b64_candidate)

    raise ValueError("unsupported binary value type")


def _decode_base64url_impl(data: str) -> bytes:
    return encoding.decode_base64url(data)


def _extract_binary_value_impl(value: Any) -> Any:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "$hex" in value:
            return encoding.decode_hex(value["$hex"])
        if "$base64" in value:
            encoded = value["$base64"]
            if not isinstance(encoded, str):
                return value
            return encoding.decode_base64(encoded)
        if "$base64url" in value:
            encoded = value["$base64url"]
            if not isinstance(encoded, str):
                return value
            return encoding.decode_base64url(encoded)
    return value


def _encode_base64url_impl(data: bytes) -> str:
    return encoding.encode_base64url(data)
