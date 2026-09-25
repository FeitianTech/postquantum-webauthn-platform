"""When two map keys are the same key, however each was written (RFC 8949 section 5.6.1).

In the generic data model an integer and a float are never equivalent, nor a
byte string and a text string, nor a tagged value and an untagged one. Within a
kind: numbers are equivalent when numerically equal (-0.0 is 0.0); two NaNs
when their significands match, zero-extended on the right to 64 bits; strings
byte for byte, however chunked; arrays item by item; maps as sets of pairs;
tags by number and content; simple values by value (``simple(21)`` is
``true``). A head's width never matters: ``1`` and ``1_0`` are one key.

``identity(node)`` is the same for two nodes exactly when they are equivalent.
The decoded value keeps one entry per identity; ``canonical`` reports a map
that holds two as ``duplicate-map-key``. A node the lenient parser could not
read (invalid, text that is not UTF-8, whole or in one chunk) is identified by
its raw bytes.
"""
from __future__ import annotations

import math
import struct
from collections.abc import Hashable, Mapping
from typing import Any

# Float width -> (struct format, significand bits) of its IEEE 754 encoding.
_FLOAT_LAYOUT = {"half": (">e", 10), "single": (">f", 23), "double": (">d", 52)}
_INFO_PRECISION = {25: "half", 26: "single", 27: "double"}
_SIMPLE_NUMBERS = {"false": 20, "true": 21, "null": 22, "undefined": 23}


def identity(node: Mapping[str, Any]) -> Hashable:
    """What makes ``node`` the key it is, in the generic data model."""

    kind = node.get("type")
    raw_text = unreadable_text_hex(node)
    if raw_text is not None:
        return ("raw", 3, raw_text)
    if kind == "invalid" or "error" in node:
        return ("raw", node.get("majorType"), node.get("hex"))
    major_type = node.get("majorType")
    if major_type in (0, 1):
        return ("integer", node.get("value"))
    if major_type == 2:
        return ("bytes", node.get("hex"))
    if major_type == 3:
        return ("text", node.get("value"))
    if major_type == 4:
        return ("array", tuple(identity(item) for item in node.get("items") or []))
    if major_type == 5:
        pairs = frozenset((identity(entry["key"]), identity(entry["value"])) for entry in node.get("entries") or [])
        return ("map", pairs)
    if major_type == 6:
        return ("tag", node.get("tag"), identity(node.get("value") or {}))
    if kind == "float" or node.get("info") in _INFO_PRECISION:
        return _float_identity(node)
    if kind == "boolean":
        return ("simple", _SIMPLE_NUMBERS["true" if node.get("value") else "false"])
    if kind in ("null", "undefined"):
        return ("simple", _SIMPLE_NUMBERS[kind])
    return ("simple", node.get("value"))


def unreadable_text_hex(node: Mapping[str, Any]) -> str | None:
    """A text string's bytes, in hex, when they are not UTF-8 -- whole, or in one of its chunks.

    The lenient parser gives such an indefinite string the ``value`` of its
    readable chunks alone, which would make it the same key as that shorter text.
    """

    if node.get("majorType") != 3:
        return None
    if "error" in node:
        return node.get("hex")
    segments = node.get("segments") or []
    if not any("error" in segment for segment in segments):
        return None
    return "".join(
        segment.get("hex", "") if "error" in segment else str(segment.get("value", "")).encode("utf-8").hex()
        for segment in segments
    )


def _float_identity(node: Mapping[str, Any]) -> Hashable:
    precision = node.get("precision") or _INFO_PRECISION[node["info"]]
    fmt, significand_bits = _FLOAT_LAYOUT[precision]
    value = node.get("value")
    if not (isinstance(value, float) and math.isnan(value)):
        return ("float", value)
    bits = node.get("argument")
    if not isinstance(bits, int):
        bits = int.from_bytes(struct.pack(fmt, value), "big")
    significand = bits & ((1 << significand_bits) - 1)
    return ("nan", significand << (64 - significand_bits))
