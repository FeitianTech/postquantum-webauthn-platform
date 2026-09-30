"""Values made JSON-safe, the one way the server does it.

Byte strings become unpadded base64url, like every byte field the server sends;
mappings and sequences are walked. The Codec shows bytes as hex instead
(``decoder.values.make_hex_only``): that is its display, not this.
``as_bytes`` is the one reading of a value as a byte string.
"""
from __future__ import annotations

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


def make_json_safe(value: Any, *, string_keys: bool = False) -> Any:
    """``value`` with every byte string as unpadded base64url.

    Keys keep their types (COSE maps are keyed by integers) unless ``string_keys``.
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
        return {
            (str(key) if string_keys else key): make_json_safe(item, string_keys=string_keys)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [make_json_safe(item, string_keys=string_keys) for item in value]
    return value
