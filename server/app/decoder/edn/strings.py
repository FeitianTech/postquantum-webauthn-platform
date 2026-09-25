"""Text in EDN: how a text string is written between double quotes, and read back.

A text string is written with JSON's escapes (RFC 8949 section 8): a quote, a
backslash, and every control character are escaped -- a carriage return
always, since an unescaped one in EDN source is dropped -- and U+2028/U+2029
too, so a line of EDN never breaks inside a string. Everything else, non-ASCII
included, is written as itself: EDN text is UTF-8.
"""
from __future__ import annotations

_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}
_READ_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


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


def read_quoted(source: str, start: int, quote_mark: str = '"') -> tuple[str, int]:
    """The string literal opening at ``source[start]``; returns its text and the offset after it.

    JSON's escapes, EDN's ``\\u{hex}`` for any scalar value, and a surrogate pair
    written as two ``\\u`` escapes. A lone surrogate, a raw control character
    other than a line feed, or a missing closing quote raises ``ValueError``
    with the offset in ``source``.
    """

    position = start + 1
    parts: list[str] = []
    while True:
        if position >= len(source):
            raise _error(start, "a string literal that is never closed")
        character = source[position]
        if character == quote_mark:
            return "".join(parts), position + 1
        if character == "\\":
            decoded, position = _read_escape(source, position, quote_mark)
            parts.append(decoded)
            continue
        if ord(character) < 0x20 and character != "\n":
            raise _error(position, f"an unescaped control character U+{ord(character):04X} in a string")
        parts.append(character)
        position += 1


def _read_escape(source: str, position: int, quote_mark: str) -> tuple[str, int]:
    if position + 1 >= len(source):
        raise _error(position, "a string literal that ends in a backslash")
    kind = source[position + 1]
    if kind == quote_mark or kind in _READ_ESCAPES:
        return _READ_ESCAPES.get(kind, kind), position + 2
    if kind == "'":
        return "'", position + 2
    if kind != "u":
        raise _error(position, f"an unknown escape \\{kind}")
    if source.startswith("{", position + 2):
        end = source.find("}", position + 3)
        digits = source[position + 3 : end] if end != -1 else ""
        if end == -1 or not digits or not all(c in "0123456789abcdefABCDEF" for c in digits):
            raise _error(position, "a \\u{...} escape without hex digits")
        code = int(digits, 16)
        if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
            raise _error(position, f"\\u{{{digits}}} is not a Unicode scalar value")
        return chr(code), end + 1
    code, after = _four_hex(source, position)
    if 0xD800 <= code <= 0xDBFF:
        if not source.startswith("\\u", after):
            raise _error(position, "a high surrogate without its low surrogate")
        low, after = _four_hex(source, after)
        if not 0xDC00 <= low <= 0xDFFF:
            raise _error(position, "a high surrogate without its low surrogate")
        return chr(0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)), after
    if 0xDC00 <= code <= 0xDFFF:
        raise _error(position, "a lone low surrogate")
    return chr(code), after


def _four_hex(source: str, position: int) -> tuple[int, int]:
    digits = source[position + 2 : position + 6]
    if len(digits) != 4 or not all(c in "0123456789abcdefABCDEF" for c in digits):
        raise _error(position, "a \\u escape without four hex digits")
    return int(digits, 16), position + 6


def _error(offset: int, reason: str) -> ValueError:
    return ValueError(f"EDN is not valid at offset {offset}: {reason}")
