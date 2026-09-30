"""Bytes a client sends, read one way for both tabs.

A value is bytes already, or text in base64url, base64 or hex
(``decode_binary_text``), decoded strictly through :mod:`server.app.encoding`:
prose pasted into a ``rawId`` is refused, never read as junk bytes. What else a
caller takes, it says: the Simple tab's stored records may hold a list of byte
values (``iterables``); the Advanced editor writes ``{"$hex": ...}``,
``{"$base64": ...}`` and ``{"$base64url": ...}`` (``wrappers``), and its request
fields read bare text as hex (``read_request_field``).
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .. import encoding

# The wrappers the Advanced editor writes, each with the one alphabet it holds.
_WRAPPERS: tuple[tuple[str, str, Callable[[str], bytes]], ...] = (
    ("$hex", "hex", encoding.decode_hex),
    ("$base64url", "base64url", encoding.decode_base64url),
    ("$base64", "base64", encoding.decode_base64),
)


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


def read(value: Any, *, iterables: bool = False, wrappers: bool = False) -> bytes:
    """A client-supplied binary value as bytes; ``ValueError`` when it is none.

    ``iterables`` takes an iterable of byte values too; ``wrappers`` takes the
    Advanced editor's ``{"$hex": ...}`` and the others, ``$`` or not, around
    text or around another value this reads.
    """

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

    if wrappers and isinstance(value, Mapping):
        for marked, plain, decoder in _WRAPPERS:
            if marked in value or plain in value:
                candidate = value.get(marked)
                if candidate is None:
                    candidate = value.get(plain)
                if isinstance(candidate, str):
                    return _read_wrapped(candidate, decoder)
                return read(candidate, iterables=iterables, wrappers=wrappers)

    if iterables and isinstance(value, Iterable):
        try:
            return bytes(value)
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError("invalid iterable value") from exc

    raise ValueError("unsupported binary value type")


def _read_wrapped(value: str, decoder: Callable[[str], bytes]) -> bytes:
    stripped = value.strip()
    if not stripped:
        raise ValueError("empty binary value")
    try:
        return decoder(stripped)
    except encoding.EncodingError as exc:
        raise ValueError("invalid binary value") from exc


def unwrap_request_value(value: Any) -> Any:
    """An Advanced request field with its ``$hex``/``$base64``/``$base64url`` wrapper decoded; anything else as given."""

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


def read_request_field(value: Any) -> Any:
    """A binary request field: a ``$hex``/``$base64``/``$base64url`` wrapper decoded, bare text read as hex."""

    decoded = unwrap_request_value(value)
    if isinstance(decoded, str):
        decoded = encoding.decode_hex(decoded)
    return decoded
