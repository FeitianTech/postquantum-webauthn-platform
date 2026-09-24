"""Text in EDN: how a text string is written between double quotes, and read back.

A text string is written with JSON's escapes (RFC 8949 section 8): a quote, a
backslash, and every control character are escaped -- a carriage return
always, since an unescaped one in EDN source is dropped -- and U+2028/U+2029
too, so a line of EDN never breaks inside a string. Everything else, non-ASCII
included, is written as itself: EDN text is UTF-8.
"""
from __future__ import annotations

_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}


def _needs_unicode_escape(character: str) -> bool:
    code = ord(character)
    return code < 0x20 or 0x7F <= code < 0xA0 or code in (0x2028, 0x2029)


def quote(text: str) -> str:
    """``text`` as an EDN (and JSON) double-quoted string literal."""

    parts = ['"']
    for character in text:
        if character in _SHORT_ESCAPES:
            parts.append(_SHORT_ESCAPES[character])
        elif _needs_unicode_escape(character):
            parts.append(f"\\u{ord(character):04x}")
        else:
            parts.append(character)
    parts.append('"')
    return "".join(parts)
