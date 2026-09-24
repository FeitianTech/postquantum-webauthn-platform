"""Decoder input that is both valid hexadecimal and a valid JSON number.

Text made only of digits (and perhaps an ``e`` exponent) reads either way:
``8101`` is the JSON number 8101 and the hex of the CBOR array ``[1]``. The
decoder never picks one silently. The precedence:

1. Hexadecimal, when the bytes are what the binary decoder reads as a CTAP
   message: an optional CTAP command or status byte, then at most one
   well-formed CBOR item, and nothing after it. ``31`` is the byte 0x31,
   PIN_INVALID; ``8101`` is ``[1]``; ``10`` is the CBOR integer 16.
2. Otherwise the JSON number: ``99`` (0x99 announces a two-byte array length
   the input does not have), ``1234`` (0x12 is 18, then a stray 0x34).

Either way the response carries an ``ambiguous-input`` finding naming the
reading it did not take. The test for well-formed CBOR is strict whether or
not the request asked for lenient decoding, so the choice never depends on it.
"""
from __future__ import annotations

import re
from typing import Any

from . import cbor_parser, ctap_prefix

_HEX_DIGITS = re.compile(r"[0-9A-Fa-f]+")


def check(text: str, parsed_json: Any) -> dict[str, Any] | None:
    """The finding for ``text`` when it reads both ways, saying which reading won."""

    if not isinstance(parsed_json, (int, float)) or isinstance(parsed_json, bool):
        return None
    if len(text) % 2 or not _HEX_DIGITS.fullmatch(text):
        return None
    if is_one_ctap_message(bytes.fromhex(text)):
        read_as, also, message = (
            "hex",
            "json",
            f"the input is also the JSON number {text}; it was read as hexadecimal, because "
            "those bytes are one well-formed CBOR item (after any CTAP command or status byte)",
        )
    else:
        read_as, also, message = (
            "json",
            "hex",
            f"the input is also hexadecimal (h'{text.lower()}'); it was read as the JSON number "
            f"{text}, because those bytes are not one well-formed CBOR item",
        )
    return {
        "code": "ambiguous-input",
        "category": "input",
        "offset": 0,
        "path": "$",
        "readAs": read_as,
        "alsoValidAs": also,
        "message": message,
    }


def is_one_ctap_message(data: bytes) -> bool:
    """A CTAP command or status byte on its own, or at most one before a single well-formed CBOR item."""

    prefix, payload = ctap_prefix._extract_ctap_prefix(data)
    if not payload:
        return prefix is not None
    try:
        _node, end, _skipped = cbor_parser.decode_item(data, len(data) - len(payload))
    except cbor_parser._CborDecodingError:
        return False
    return end == len(data)
