"""The framing of a CTAP message the encoder rebuilds: ``data.ctap``, which the decoder gives beside its view.

``code`` is the command or status byte to write before the message, or null for
none; ``message`` which CTAP message the view is; ``trailingBytesHex`` the bytes
after it. The encoder takes them as they are: it adds no byte the view did not
come with, and drops none that followed it.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from ... import encoding


def require(framing: Mapping[str, Any] | None, view: str) -> Mapping[str, Any]:
    """``data.ctap``, which a CTAP view is encoded with; refuses a view without it."""

    if framing is None:
        raise ValueError(
            f"{view} is encoded with the ctap object the decoder gives beside it: its code is the command or "
            "status byte sent before the message (null for none), its trailingBytesHex any bytes after it."
        )
    if "code" not in framing:
        raise ValueError("ctap.code is missing: the command or status byte sent before the message (0 to 255), or null for none.")
    code = framing["code"]
    if code is not None and (isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 0xFF):
        raise ValueError(f"ctap.code must be a byte (0 to 255), or null for none; it is {json.dumps(code)}.")
    trailing = framing.get("trailingBytesHex")
    if trailing is not None and (not isinstance(trailing, str) or encoding.try_decode_hex(trailing) is None):
        raise ValueError("ctap.trailingBytesHex must be hex.")
    return framing


def message(framing: Mapping[str, Any], view: str) -> str:
    """The CTAP message ``framing`` says the view is."""

    named = framing.get("message")
    if not isinstance(named, str) or not named:
        raise ValueError(f"{view} is encoded as the CTAP message ctap.message names; it names none.")
    return named


def check_message(framing: Mapping[str, Any], shown: str | None) -> None:
    """Refuse a view whose message is not the one its framing names."""

    named = framing.get("message")
    if named is not None and named != shown:
        raise ValueError(f"ctapDecoded shows a {shown}, but ctap.message says it is a {named}.")


def frame(framing: Mapping[str, Any], payload: bytes) -> bytes:
    """``payload`` with the byte before it and the bytes after it that ``framing`` holds."""

    code = framing.get("code")
    trailing = encoding.decode_hex(framing.get("trailingBytesHex") or "")
    return (b"" if code is None else bytes([code])) + payload + trailing
