"""Text the decoder reads as bytes: hexadecimal, base64 or base64url, and which one it was."""
from __future__ import annotations

import re
from typing import Any

from ...encoding import EncodingError, SniffResult, sniff


def sniff_binary_input(value: str) -> SniffResult:
    """Decode decoder input and report which encoding actually matched.

    The label comes from the decoder that succeeded, not from scanning the
    input for ``-``/``_``: a base64url payload that happens to use none of
    those characters is byte-identical to the same text read as standard
    base64, and :attr:`~server.app.encoding.SniffResult.ambiguous` says so
    instead of the decoder picking one and asserting it.
    """

    if not "".join(value.split()):
        raise ValueError("No binary data present.")

    try:
        return sniff(value)
    except EncodingError as exc:
        digits = odd_hex_digits(value)
        if digits:
            raise ValueError(
                f"Input is {digits} hexadecimal digits, an odd number, so no bytes; and it is not base64 either."
            ) from exc
        raise ValueError(
            "Input does not appear to be valid base64, base64url, or hexadecimal data."
        ) from exc


_HEX_TEXT = re.compile(r"(?:0[xX])?[0-9A-Fa-f:]+")


def odd_hex_digits(value: str) -> int:
    """How many hexadecimal digits ``value`` is, when it is an odd number of them; else 0."""

    text = "".join(value.split())
    digits = len(text.removeprefix("0x").removeprefix("0X").replace(":", ""))
    return digits if _HEX_TEXT.fullmatch(text) and digits % 2 else 0


def decode_binary_input(value: str) -> tuple[bytes, str]:
    result = sniff_binary_input(value)
    # Text in the alphabet base64 and base64url share decodes to the same bytes
    # in either: the label says both rather than asserting one.
    return result.data, "base64 or base64url" if result.ambiguous else result.encoding


def decode_binary_field(value: Any) -> tuple[bytes, str] | None:
    if isinstance(value, str):
        try:
            return decode_binary_input(value)
        except ValueError:
            return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value), "binary"
    return None
