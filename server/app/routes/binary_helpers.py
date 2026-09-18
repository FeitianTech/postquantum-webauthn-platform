"""Binary helpers shared by the simple and advanced credential intake paths.

``advanced_parts/binary_helpers_impl.py`` and ``simple/binary_helpers_impl.py``
each carried their own copy of these, and the copies had drifted: one stripped
surrounding whitespace and the other did not, and both decoded with
``validate=False``, so prose pasted into a ``rawId`` produced junk bytes instead
of a rejection. There is one copy now, and it decodes strictly through
:mod:`server.app.encoding`.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .. import encoding


def decode_base64url_bytes(value: Any) -> bytes:
    """Return ``value`` as bytes, or ``b""`` when it is not valid base64url.

    Callers use the empty result as "absent". Input outside the base64url
    alphabet is absent, not a licence to decode whatever characters remain.
    """

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return encoding.try_decode_base64url(value) or b""
    return b""


def extract_assertion_credential_id(response: Mapping[str, Any]) -> bytes | None:
    """Return the credential ID from an assertion response, or ``None``."""

    raw_id: Any = None
    if isinstance(response, Mapping):
        raw_id = response.get("rawId") or response.get("id")

    if isinstance(raw_id, (bytes, bytearray, memoryview)):
        return bytes(raw_id)

    if isinstance(raw_id, str):
        return decode_base64url_bytes(raw_id) or None

    return None


def decode_binary_text(value: str) -> bytes:
    """Decode a client-supplied binary string in base64url, base64, or hex.

    The three alphabets are checked strictly, which makes the order irrelevant
    for the base64 pair: ``-``/``_`` is only valid base64url and ``+``/``/`` is
    only valid base64, so a payload can no longer match the wrong one and come
    back as different bytes.

    Base64 is still tried before hex, as it always was, so an even-length
    string of hex digits is read as base64 -- it is valid base64 too, and
    changing that would silently reinterpret existing credential IDs. Internal
    whitespace disqualifies base64 (it cannot appear in a wire value) and is
    left for the hex reading, where ``41 42 43`` means three bytes.
    """

    candidate = value.strip()
    if not candidate:
        raise encoding.EncodingError("empty binary value")

    for decoder in (encoding.try_decode_base64url, encoding.try_decode_base64):
        decoded = decoder(candidate, ignore_whitespace=False)
        if decoded is not None:
            return decoded

    return encoding.decode_hex(candidate, allow_separators=True)
