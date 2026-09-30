"""Values made JSON-safe, the one way the server does it.

Byte strings become unpadded base64url, like every byte field the server sends;
mappings and sequences are walked. The Codec shows bytes as hex instead
(``decoder.decode.keys.hex_json_safe``): that is its display, not this.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fido2.utils import ByteBuffer

from .encoding import encode_base64url

__all__ = ["make_json_safe"]


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
