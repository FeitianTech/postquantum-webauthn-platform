"""Key and binary coercion helpers for decoder internals."""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple

from fido2.utils import ByteBuffer

MISSING = object()


def int_to_key_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big", signed=False)


def generate_key_variants(key: Any) -> Iterable[Any]:
    yield key

    if isinstance(key, int):
        yield str(key)
        if key >= 0:
            yield int_to_key_bytes(key)
        return

    if isinstance(key, str):
        stripped = key.strip()
        if not stripped:
            return
        if stripped.isdigit():
            numeric = int(stripped, 10)
            yield numeric
            if numeric >= 0:
                yield int_to_key_bytes(numeric)
        elif stripped.lower().startswith("0x"):
            try:
                numeric = int(stripped, 16)
            except ValueError:
                return
            yield numeric
            if numeric >= 0:
                yield int_to_key_bytes(numeric)
        return

    if isinstance(key, (bytes, bytearray)):
        raw = bytes(key)
        yield raw
        if 1 <= len(raw) <= 8:
            numeric = int.from_bytes(raw, "big", signed=False)
            yield numeric
            yield str(numeric)
        return

    if isinstance(key, ByteBuffer):
        raw = key.getvalue()
        yield raw
        if 1 <= len(raw) <= 8:
            numeric = int.from_bytes(raw, "big", signed=False)
            yield numeric
            yield str(numeric)


def key_variant_identity(key: Any) -> Tuple[str, Any]:
    if isinstance(key, (bytes, bytearray)):
        return ("bytes", bytes(key))
    return ("other", key)


def get_mapping_entry(mapping: Mapping[Any, Any], *keys: Any) -> Any:
    if not isinstance(mapping, Mapping):
        return MISSING

    seen: set = set()
    for original in keys:
        for variant in generate_key_variants(original):
            identity = key_variant_identity(variant)
            if identity in seen:
                continue
            seen.add(identity)
            candidate = mapping.get(variant, MISSING)
            if candidate is not MISSING:
                return candidate
    return MISSING


def coerce_cbor_bytes(value: Any) -> Optional[bytes]:
    if isinstance(value, ByteBuffer):
        return value.getvalue()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return None


def stringify_mapping_keys(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): stringify_mapping_keys(val) for key, val in value.items()}
    if isinstance(value, list):
        return [stringify_mapping_keys(item) for item in value]
    return value


def make_hex_only(value: Any) -> Any:
    if isinstance(value, ByteBuffer):
        return value.getvalue().hex()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, Mapping):
        return {str(key): make_hex_only(val) for key, val in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [make_hex_only(item) for item in value]
    return value


def hex_json_safe(value: Any) -> Any:
    return make_hex_only(value)
