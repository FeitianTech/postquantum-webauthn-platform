"""Key and binary coercion helpers for decoder internals."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from fido2.utils import ByteBuffer

from .cbor_parser import CborDiagnostic

MISSING = object()


def key_identity(key: Any) -> tuple[str, Any]:
    """What makes a map key the key it is: its CBOR type and its value.

    1, "1" and h'01' are three different CBOR map keys; Python would still fold
    1 and True together, so a bool never stands in for an integer.
    """

    if isinstance(key, bool):
        return ("bool", key)
    if isinstance(key, int):
        return ("int", key)
    if isinstance(key, str):
        return ("text", key)
    if isinstance(key, ByteBuffer):
        return ("bytes", key.getvalue())
    if isinstance(key, (bytes, bytearray, memoryview)):
        return ("bytes", bytes(key))
    return ("other", key)


def get_mapping_entry(mapping: Mapping[Any, Any], *keys: Any) -> Any:
    """Return the value under the first of ``keys`` the map has, by exact key type.

    CTAP numbers its members with integer keys: only the integer 1 is member 1,
    never a text "1" or a byte string h'01'.
    """

    if not isinstance(mapping, Mapping):
        return MISSING

    entries: dict[tuple[str, Any], Any] = {}
    for key, value in mapping.items():
        entries.setdefault(key_identity(key), value)
    for key in keys:
        candidate = entries.get(key_identity(key), MISSING)
        if candidate is not MISSING:
            return candidate
    return MISSING


def coerce_cbor_bytes(value: Any) -> bytes | None:
    if isinstance(value, ByteBuffer):
        return value.getvalue()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return None


def key_text(key: Any) -> str:
    """Spell a map key for JSON: a byte string as hex, like a byte string value."""

    if isinstance(key, ByteBuffer):
        return key.getvalue().hex()
    if isinstance(key, (bytes, bytearray, memoryview)):
        return bytes(key).hex()
    return str(key)


def stringify_mapping_keys(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key_text(key): stringify_mapping_keys(val) for key, val in value.items()}
    if isinstance(value, list):
        return [stringify_mapping_keys(item) for item in value]
    return value


def make_hex_only(value: Any) -> Any:
    if isinstance(value, CborDiagnostic):
        return {"diagnostic": value.diagnostic}
    if isinstance(value, ByteBuffer):
        return value.getvalue().hex()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, Mapping):
        return {key_text(key): make_hex_only(val) for key, val in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [make_hex_only(item) for item in value]
    return value


def hex_json_safe(value: Any) -> Any:
    return make_hex_only(value)
