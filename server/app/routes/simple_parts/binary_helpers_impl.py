from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping, Sequence
from typing import Any


def _add_base64_padding_impl(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _decode_base64url_bytes_impl(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return b""
        padding = "=" * (-len(candidate) % 4)
        try:
            return base64.urlsafe_b64decode(candidate + padding)
        except Exception:
            return b""
    return b""


def _extract_assertion_credential_id_impl(
    response: Mapping[str, Any]
) -> bytes | None:
    raw_id: Any = None
    if isinstance(response, Mapping):
        raw_id = response.get("rawId") or response.get("id")

    if isinstance(raw_id, (bytes, bytearray, memoryview)):
        return bytes(raw_id)

    if isinstance(raw_id, str):
        return _decode_base64url_bytes_impl(raw_id) or None

    return None


def _decode_binary_value_impl(value: Any) -> bytes:
    if value is None:
        raise ValueError("missing binary value")

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            raise ValueError("empty string")

        try:
            return base64.urlsafe_b64decode(_add_base64_padding_impl(candidate))
        except Exception:
            pass

        try:
            return base64.b64decode(_add_base64_padding_impl(candidate))
        except Exception:
            pass

        try:
            return bytes.fromhex(candidate)
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError("invalid binary value") from exc

    if isinstance(value, Iterable):
        try:
            return bytes(value)
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError("invalid iterable value") from exc

    raise ValueError("unsupported binary value type")


def _select_first_impl(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None
