from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Sequence


def _add_base64_padding_impl(_simple_module: Any, value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _decode_base64url_bytes_impl(simple_module: Any, value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return b""
        padding = "=" * (-len(candidate) % 4)
        try:
            return simple_module.base64.urlsafe_b64decode(candidate + padding)
        except Exception:
            return b""
    return b""


def _extract_assertion_credential_id_impl(
    simple_module: Any, response: Mapping[str, Any]
) -> Optional[bytes]:
    raw_id: Any = None
    if isinstance(response, Mapping):
        raw_id = response.get("rawId") or response.get("id")

    if isinstance(raw_id, (bytes, bytearray, memoryview)):
        return bytes(raw_id)

    if isinstance(raw_id, str):
        return simple_module._decode_base64url_bytes(raw_id) or None

    return None


def _decode_binary_value_impl(simple_module: Any, value: Any) -> bytes:
    if value is None:
        raise ValueError("missing binary value")

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            raise ValueError("empty string")

        try:
            return simple_module.base64.urlsafe_b64decode(simple_module._add_base64_padding(candidate))
        except Exception:
            pass

        try:
            return simple_module.base64.b64decode(simple_module._add_base64_padding(candidate))
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


def _select_first_impl(_simple_module: Any, mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None
