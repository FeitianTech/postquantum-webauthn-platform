"""EDN text to the exact bytes it notates: the encoder's EDN input.

It reads what ``spell`` writes -- so a decoded item's EDN encodes back to the
bytes it was decoded from -- and the rest of RFC 8949 section 8 and RFC 8610
appendix G that a person writes by hand: decimal, hex, octal and binary
integers; decimal and hex floats; ``h''``, ``b64''`` and single-quoted byte
strings; embedded CBOR ``<<...>>``; ``(_ ...)``, ``ilbs<<...>>`` and
``ilts<<...>>`` for indefinite-length strings; ``float'..'``; tags; ``simple(n)``;
encoding indicators ``_i`` and ``_0``..``_3`` (``_`` for an indefinite length);
``/.../``, ``/*...*/``, ``#`` and ``//`` comments; commas optional between
items, as the EDN draft allows, and a trailing one.

Written exactly as notated: map order, duplicate keys, head widths and float
widths are the text's, never canonicalised. Refused, each with the offset in
the text: reserved indicators ``_4``..``_7``, an indicator too narrow for its
value, a float not exact at its width, a float literal beyond the range of a
double (rather than rounded to infinity), ``simple(24)``..``simple(31)``, more than
one top-level item (a CBOR sequence), items nested more than 64 deep (the
decoder's limit), and an integer beyond 64 bits -- which the
EDN draft (section 2.2) reads as a bignum tag; here it must be written as one,
``2(h'..')``, so that the tag is visible in the text.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
from collections.abc import Callable

from ..cbor_head import INDEFINITE, encode_head
from . import floats, strings

_NUMBER = re.compile(
    r"""[+-]?(?:
        0[xX](?:[0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?|\.[0-9a-fA-F]+)[pP][+-]?[0-9]+
      | 0[xX][0-9a-fA-F]+ | 0[oO][0-7]+ | 0[bB][01]+
      | (?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?
    )""",
    re.VERBOSE,
)
_SPEC = re.compile(r"_[A-Za-z0-9_]*")
_WORDS = {
    "false": b"\xf4", "true": b"\xf5", "null": b"\xf6", "undefined": b"\xf7",
}
_MAX_ARGUMENT = (1 << 64) - 1
_BEYOND_64_BITS = "an integer beyond 64 bits: write it as a bignum tag, 2(h'..') or 3(h'..')"
# decode/cbor_parser's limit: an item nested more than 64 deep is refused, so
# whatever this reader writes, the decoder reads. Embedded CBOR counts too.
_MAX_DEPTH = 64


def encode(text: str) -> bytes:
    """The bytes of the one CBOR item ``text`` notates; ``ValueError`` names the offset where it goes wrong."""

    reader = _Reader(text)
    reader.skip()
    if reader.at_end():
        raise reader.error("there is no item to encode")
    item = reader.item()
    reader.skip()
    if not reader.at_end():
        raise reader.error("more than one item follows: a CBOR sequence cannot be encoded as one item")
    return item


class _Reader:
    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0
        self.depth = 0

    # -- positions, blank space and comments ---------------------------------------

    def error(self, reason: str, offset: int | None = None) -> ValueError:
        return ValueError(f"EDN is not valid at offset {self.position if offset is None else offset}: {reason}")

    def at_end(self) -> bool:
        return self.position >= len(self.text)

    def peek(self, length: int = 1) -> str:
        return self.text[self.position : self.position + length]

    def expect(self, literal: str) -> None:
        if not self.text.startswith(literal, self.position):
            raise self.error(f"expected {literal!r}")
        self.position += len(literal)

    def skip(self) -> bool:
        """Skip blank space and comments; whether any was there."""

        start = self.position
        text = self.text
        while self.position < len(text):
            character = text[self.position]
            if character in " \t\r\n":
                self.position += 1
            elif character == "#" or text.startswith("//", self.position):
                end = text.find("\n", self.position)
                self.position = len(text) if end == -1 else end + 1
            elif text.startswith("/*", self.position):
                end = text.find("*/", self.position + 2)
                if end == -1:
                    raise self.error("a /* comment that is never closed")
                self.position = end + 2
            elif character == "/":
                end = text.find("/", self.position + 1)
                if end == -1:
                    raise self.error("a / comment that is never closed")
                self.position = end + 1
            else:
                break
        return self.position != start

    def spec(self) -> str | None:
        """The encoding indicator right after a literal (``_0``, ``_``, ``_i``), without its underscore."""

        match = _SPEC.match(self.text, self.position)
        if not match:
            return None
        self.position = match.end()
        return match.group()[1:]

    def head_info(self, spec: str | None, start: int, *, indefinite_allowed: bool) -> int | None:
        """The additional information an indicator names: ``None`` for the shortest."""

        if spec is None:
            return None
        if spec == "":
            if not indefinite_allowed:
                raise self.error("an indefinite length is only for strings, arrays and maps", start)
            return INDEFINITE
        if spec == "i":
            return -1
        if spec in ("0", "1", "2", "3"):
            return 24 + int(spec)
        if spec in ("4", "5", "6", "7"):
            raise self.error(f"encoding indicator _{spec} is reserved", start)
        raise self.error(f"no encoding indicator _{spec}", start)

    def head(self, major_type: int, argument: int | None, info: int | None, start: int) -> bytes:
        if info == -1:  # _i: the argument in the initial byte itself
            if argument >= 24:
                raise self.error(f"_i holds an argument of 0..23 in the initial byte, not {argument}", start)
            info = argument
        try:
            return encode_head(major_type, argument, info)
        except ValueError as exc:
            raise self.error(str(exc), start) from None

    # -- items -----------------------------------------------------------------------

    def item(self) -> bytes:
        if self.depth > _MAX_DEPTH:
            raise self.error(f"items are nested more than {_MAX_DEPTH} deep")
        self.depth += 1
        try:
            return self._item()
        finally:
            self.depth -= 1

    def _item(self) -> bytes:
        start = self.position
        character = self.peek()
        if character == "[":
            return self.container("[", "]", 4, pairs=False)
        if character == "{":
            return self.container("{", "}", 5, pairs=True)
        if character == '"':
            return self.text_string(start)
        if character == "'":
            return self.quoted_bytes(start)
        if self.text.startswith("(_", self.position):
            return self.stream_string(start)
        if self.text.startswith("<<", self.position):
            return self.embedded(start)
        for prefix, read in (("h'", self.hex_bytes), ("b64'", self.base64_bytes), ("float'", self.float_bits),
                             ("ilbs<<", self.indefinite_sequence), ("ilts<<", self.indefinite_sequence)):
            if self.text.startswith(prefix, self.position):
                return read(start, prefix)
        if self.text.startswith("simple(", self.position):
            return self.simple(start)
        for word, encoded in _WORDS.items():
            if self._word(word):
                return encoded
        return self.number(start)

    def _word(self, word: str) -> bool:
        end = self.position + len(word)
        if self.text.startswith(word, self.position) and not self.text[end : end + 1].isalnum():
            self.position = end
            return True
        return False

    def number(self, start: int) -> bytes:
        for word, value in (("NaN", float("nan")), ("Infinity", float("inf")), ("-Infinity", float("-inf"))):
            if self._word(word):
                return self.float_value(value, start)
        match = _NUMBER.match(self.text, self.position)
        if not match:
            raise self.error("expected an item", start)
        literal = match.group()
        self.position = match.end()
        body = literal.lstrip("+-")
        if body[:2].lower() == "0x" and "p" in body.lower():
            return self.float_literal(literal, float.fromhex, start)
        if any(c in body for c in ".eE") and body[:2].lower() != "0x":
            return self.float_literal(literal, float, start)
        try:
            value = int(literal.replace("+", ""), 0) if body[:2].lower() in ("0x", "0o", "0b") else int(literal)
        except ValueError:
            # Python converts at most 4300 decimal digits: far beyond 64 bits in any case.
            raise self.error(_BEYOND_64_BITS, start) from None
        return self.integer(value, start, signed=literal[0] in "+-")

    def float_literal(self, literal: str, read: Callable[[str], float], start: int) -> bytes:
        """A decimal or hex float literal: finite, or refused -- never rounded to infinity."""

        try:
            value = read(literal)
        except OverflowError:
            value = math.inf
        if math.isinf(value):
            raise self.error(f"{literal} is beyond the range of a double; Infinity is written Infinity", start)
        return self.float_value(value, start)

    def float_value(self, value: float, start: int) -> bytes:
        spec = self.spec()
        if spec is not None and spec not in ("1", "2", "3"):
            raise self.error(f"a float's width is _1, _2 or _3, not _{spec}", start)
        try:
            return floats.encode(value, int(spec) if spec else None)
        except ValueError as exc:
            raise self.error(str(exc), start) from None

    def integer(self, value: int, start: int, *, signed: bool = False) -> bytes:
        if not -(1 << 64) <= value <= _MAX_ARGUMENT:
            raise self.error(_BEYOND_64_BITS, start)
        info = self.head_info(self.spec(), start, indefinite_allowed=False)
        if self.peek() == "(":
            # RFC 8949 section 8: a tag number is an unsigned integer; -0(1) is not tag 0.
            if signed:
                raise self.error("a tag number is an unsigned integer, written without a sign", start)
            return self.tag(value, info, start)
        major_type, argument = (0, value) if value >= 0 else (1, -1 - value)
        return self.head(major_type, argument, info, start)

    def tag(self, number: int, info: int | None, start: int) -> bytes:
        self.expect("(")
        self.skip()
        content = self.item()
        self.skip()
        self.expect(")")
        return self.head(6, number, info, start) + content

    def simple(self, start: int) -> bytes:
        self.expect("simple(")
        match = re.compile(r"[0-9]+").match(self.text, self.position)
        if not match:
            raise self.error("simple() takes a decimal number")
        self.position = match.end()
        self.expect(")")
        value = int(match.group())
        if 24 <= value <= 31 or value > 255:
            raise self.error(f"simple({value}) is not a simple value: 0..23 and 32..255 are", start)
        return bytes([0xE0 | value]) if value < 24 else bytes([0xF8, value])

    # -- strings ---------------------------------------------------------------------

    def string(self, major_type: int, content: bytes, start: int, *, empty_indefinite: bytes) -> bytes:
        info = self.head_info(self.spec(), start, indefinite_allowed=True)
        if info == INDEFINITE:
            if content:
                raise self.error("only an empty literal takes _ (an indefinite string with no chunks)", start)
            return empty_indefinite
        return self.head(major_type, len(content), info, start) + content

    def text_string(self, start: int) -> bytes:
        value, self.position = strings.read_quoted(self.text, self.position)
        return self.string(3, value.encode("utf-8"), start, empty_indefinite=b"\x7f\xff")

    def quoted_bytes(self, start: int) -> bytes:
        value, self.position = strings.read_quoted(self.text, self.position, "'")
        return self.string(2, value.encode("utf-8"), start, empty_indefinite=b"\x5f\xff")

    def _closing_quote(self, prefix: str) -> str:
        end = self.text.find("'", self.position + len(prefix))
        if end == -1:
            raise self.error(f"a {prefix}...' literal that is never closed")
        body = self.text[self.position + len(prefix) : end]
        self.position = end + 1
        return body

    def hex_bytes(self, start: int, prefix: str) -> bytes:
        digits = re.sub(r"\s+", "", self._closing_quote(prefix))
        if len(digits) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", digits):
            raise self.error("h'..' holds pairs of hex digits", start)
        return self.string(2, bytes.fromhex(digits), start, empty_indefinite=b"\x5f\xff")

    def base64_bytes(self, start: int, prefix: str) -> bytes:
        # Either alphabet, the padding optional.
        body = re.sub(r"\s+", "", self._closing_quote(prefix)).replace("-", "+").replace("_", "/")
        if "=" not in body:
            body += "=" * (-len(body) % 4)
        try:
            content = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            raise self.error("b64'..' is not base64", start) from None
        return self.string(2, content, start, empty_indefinite=b"\x5f\xff")

    def float_bits(self, start: int, prefix: str) -> bytes:
        digits = re.sub(r"\s+", "", self._closing_quote(prefix))
        if len(digits) not in (4, 8, 16) or not re.fullmatch(r"[0-9a-fA-F]+", digits):
            raise self.error("float'..' holds the 2, 4 or 8 bytes of an IEEE 754 float, in hex", start)
        if self.spec() is not None:
            raise self.error("float'..' takes no encoding indicator: its length is its width", start)
        return bytes([0xF8 + {4: 1, 8: 2, 16: 3}[len(digits)]]) + bytes.fromhex(digits)

    def stream_string(self, start: int) -> bytes:
        self.expect("(_")
        if not self.skip():
            raise self.error("(_ is followed by blank space")
        starts: list[int] = []
        chunks = self.sequence(")", starts)
        self.expect(")")
        return self.indefinite_string(list(zip(starts, chunks)), start)

    def indefinite_sequence(self, start: int, prefix: str) -> bytes:
        self.position += len(prefix)
        starts: list[int] = []
        chunks = self.sequence(">>", starts)
        self.expect(">>")
        if not chunks:
            return b"\x5f\xff" if prefix == "ilbs<<" else b"\x7f\xff"
        return self.indefinite_string(list(zip(starts, chunks)), start, 2 if prefix == "ilbs<<" else 3)

    def indefinite_string(self, chunks: list[tuple[int, bytes]], start: int, major_type: int | None = None) -> bytes:
        """``(_ ...)``: the chunks, each at its offset in the text, are definite strings of one type."""

        if not chunks:
            raise self.error("(_ ) names no chunks: write ''_ or \"\"_ for an empty indefinite string", start)
        if major_type is None:
            major_type = chunks[0][1][0] >> 5
        for offset, chunk in chunks:
            if chunk[0] >> 5 not in (2, 3):
                raise self.error("a chunk of an indefinite-length string is a byte or text string", offset)
            if chunk[0] >> 5 != major_type or chunk[0] & 0x1F == INDEFINITE:
                raise self.error("an indefinite string's chunks are definite strings of its own type", offset)
        return self.head(major_type, None, INDEFINITE, start) + b"".join(chunk for _, chunk in chunks) + b"\xff"

    def embedded(self, start: int) -> bytes:
        self.expect("<<")
        content = b"".join(self.sequence(">>"))
        self.expect(">>")
        return self.string(2, content, start, empty_indefinite=b"\x5f\xff")

    # -- containers --------------------------------------------------------------------

    def sequence(self, closing: str, starts: list[int] | None = None) -> list[bytes]:
        """Items up to ``closing``: separated by a comma or blank space, a trailing comma allowed.

        ``starts``, when given, receives the offset in the text where each item starts.
        """

        items: list[bytes] = []
        self.skip()
        while not self.text.startswith(closing, self.position):
            if self.at_end():
                raise self.error(f"expected {closing!r}")
            if starts is not None:
                starts.append(self.position)
            items.append(self.item())
            separated = self.skip()
            if self.at_end():
                raise self.error(f"expected {closing!r}")
            if self.peek() == ",":
                self.position += 1
                self.skip()
            elif not separated and not self.text.startswith(closing, self.position):
                raise self.error("items are separated by a comma or blank space")
        return items

    def container(self, opening: str, closing: str, major_type: int, *, pairs: bool) -> bytes:
        start = self.position
        self.expect(opening)
        info = self.head_info(self.spec(), start, indefinite_allowed=True)
        if info is not None and not self.skip() and self.peek() != closing:
            raise self.error("an encoding indicator is followed by blank space before the first item")
        parts = self.entries(closing) if pairs else self.sequence(closing)
        self.expect(closing)
        count = len(parts) // 2 if pairs else len(parts)
        if info == INDEFINITE:
            return self.head(major_type, None, INDEFINITE, start) + b"".join(parts) + b"\xff"
        return self.head(major_type, count, info, start) + b"".join(parts)

    def entries(self, closing: str) -> list[bytes]:
        parts: list[bytes] = []
        self.skip()
        while not self.text.startswith(closing, self.position):
            if self.at_end():
                raise self.error(f"expected {closing!r}")
            parts.append(self.item())
            self.skip()
            self.expect(":")
            self.skip()
            parts.append(self.item())
            separated = self.skip()
            if self.at_end():
                raise self.error(f"expected {closing!r}")
            if self.peek() == ",":
                self.position += 1
                self.skip()
            elif not separated and not self.text.startswith(closing, self.position):
                raise self.error("entries are separated by a comma or blank space")
        return parts
