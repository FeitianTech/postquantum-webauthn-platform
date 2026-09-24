"""Floating-point values in EDN, at the width they were written.

RFC 8949 section 8.1: a float is written as its value, followed by ``_1``,
``_2`` or ``_3`` when it is encoded at half, single or double precision and
that is not the shortest width holding the value exactly (preferred
serialization). ``NaN`` is the quiet NaN without a payload; any other NaN --
a payload, a sign bit -- has no decimal spelling and is written
``float'<its IEEE 754 bytes in hex>'`` (draft-ietf-cbor-edn-literals section
3.8), whose length gives the width.
"""
from __future__ import annotations

import math
import struct
from collections.abc import Mapping
from typing import Any

# Encoding indicator digit -> (bytes, struct format) of that IEEE 754 width.
WIDTHS = {1: (2, ">e"), 2: (4, ">f"), 3: (8, ">d")}
# The quiet NaN with no payload -- what EDN's ``NaN`` is -- at each width.
QUIET_NAN = {1: 0x7E00, 2: 0x7FC00000, 3: 0x7FF8000000000000}
_PRECISION_WIDTH = {"half": 1, "single": 2, "double": 3}


def shortest_width(value: float) -> int:
    """The width of ``value``'s preferred serialization: the shortest that holds it exactly."""

    for width, (_size, fmt) in WIDTHS.items():
        try:
            back = struct.unpack(fmt, struct.pack(fmt, value))[0]
        except (OverflowError, struct.error):
            continue
        if back == value and math.copysign(1.0, back) == math.copysign(1.0, value):
            return width
    return 3


def decimal(value: float) -> str:
    """The shortest decimal that reads back as ``value``, always with a fraction.

    Python's ``repr`` gives the shortest round-trip decimal; ``1e+16`` becomes
    ``1.0e+16`` so that no reader can take it for an integer.
    """

    mantissa, marker, exponent = repr(value).partition("e")
    if "." not in mantissa:
        mantissa += ".0"
    return f"{mantissa}{marker}{exponent}"


def spell(node: Mapping[str, Any]) -> str:
    """A float node from the parser, exactly: its value, and its width where not preferred."""

    width = _width(node)
    size, fmt = WIDTHS[width]
    bits = node.get("argument")
    if not isinstance(bits, int):
        bits = int.from_bytes(struct.pack(fmt, node["value"]), "big")
    value = struct.unpack(fmt, bits.to_bytes(size, "big"))[0]
    if math.isnan(value):
        if bits == QUIET_NAN[width]:
            return "NaN" if width == 1 else f"NaN_{width}"
        return f"float'{bits:0{2 * size}x}'"
    if math.isinf(value):
        text, preferred = ("Infinity" if value > 0 else "-Infinity"), 1
    else:
        text, preferred = decimal(value), shortest_width(value)
    return text if width == preferred else f"{text}_{width}"


def _width(node: Mapping[str, Any]) -> int:
    info = node.get("info")
    if isinstance(info, int) and 25 <= info <= 27:
        return info - 24
    precision = node.get("precision")
    if precision in _PRECISION_WIDTH:
        return _PRECISION_WIDTH[precision]
    raise ValueError("a float node without its width")
