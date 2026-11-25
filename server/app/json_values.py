"""Values made JSON-safe, the one way the server does it.

Byte strings become unpadded base64url, like every byte field the server sends;
mappings and sequences are walked. The Codec shows bytes as hex instead
(``decoder.values.make_hex_only``): that is its display, not this.
``as_bytes`` is the one reading of a value as a byte string.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fido2.utils import ByteBuffer

from .encoding import encode_base64url

__all__ = ["as_bytes", "make_json_safe"]


def as_bytes(value: Any) -> bytes | None:
    """``value`` as ``bytes`` when it is a byte string (``ByteBuffer`` included), else ``None``."""

    if isinstance(value, ByteBuffer):
        return value.getvalue()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return None


def make_json_safe(value: Any, *, string_keys: bool = False, writable_keys: bool = False) -> Any:
    """``value`` with every byte string as unpadded base64url.

    Keys keep their types (COSE maps are keyed by integers) unless ``string_keys``.
    With ``writable_keys``, a map whose keys JSON cannot write sorted (a byte string
    among them, or text beside integers) has every key as the text JSON would write,
    a byte string as base64url; where two keys become one text, the later entry wins.
    A datetime becomes its UTC ISO 8601 text, to the second; a UUID its string.
    """

    if isinstance(value, ByteBuffer):
        return encode_base64url(value.getvalue())
    if isinstance(value, (bytes, bytearray, memoryview)):
        return encode_base64url(bytes(value))
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Mapping):
        as_text = string_keys or (writable_keys and not _keys_sort(value))
        spell = str if string_keys else _key_text
        return {
            (spell(key) if as_text else key): make_json_safe(
                item, string_keys=string_keys, writable_keys=writable_keys
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [make_json_safe(item, string_keys=string_keys, writable_keys=writable_keys) for item in value]
    return value


def _keys_sort(mapping: Mapping[Any, Any]) -> bool:
    """Whether ``mapping``'s keys are all text or all integers (booleans among them), which JSON writes sorted."""

    return all(isinstance(key, str) for key in mapping) or all(isinstance(key, int) for key in mapping)


def _key_text(key: Any) -> str:
    """``key`` as JSON writes a key, a byte string as base64url like a byte string value."""

    if isinstance(key, str):
        return key
    raw = as_bytes(key)
    return encode_base64url(raw) if raw is not None else json.dumps(key)
