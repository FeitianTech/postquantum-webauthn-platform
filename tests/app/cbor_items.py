"""Hypothesis strategies that write CBOR data items byte by byte, every way RFC 8949 allows.

Each strategy draws an item's bytes directly -- not a Python value run through
an encoder -- so it reaches what an encoder never writes: every legal head width
for every argument, indefinite lengths with chunks of their own widths and with
no chunks, maps with duplicate keys in any order, tags inside tags, simple
values, and floats of any bit pattern (NaN payloads, a signed NaN, subnormals,
both zeros, both infinities). The heads are written here, not with the code
under test. ``hypothesis.event`` labels what each example holds, so
``--hypothesis-show-statistics`` counts every feature.
"""
from __future__ import annotations

import math
import struct

from hypothesis import event
from hypothesis import strategies as st

_WIDTH_BYTES = {24: 1, 25: 2, 26: 4, 27: 8}
_BOUNDARIES = [0, 1, 23, 24, 255, 256, 65535, 65536, 2**32 - 1, 2**32, 2**64 - 1]


def _shortest(argument: int) -> int:
    if argument < 24:
        return argument
    return next(info for info, width in _WIDTH_BYTES.items() if argument < 1 << (8 * width))


@st.composite
def head(draw, major_type: int, argument: int) -> bytes:
    """A head for ``argument``, at any width that holds it: the shortest or a wider one."""

    infos = ([argument] if argument < 24 else []) + [
        info for info, width in _WIDTH_BYTES.items() if argument < 1 << (8 * width)
    ]
    info = draw(st.sampled_from(infos))
    if info != _shortest(argument):
        event("head wider than its argument needs")
    if info < 24:
        return bytes([(major_type << 5) | info])
    return bytes([(major_type << 5) | info]) + argument.to_bytes(_WIDTH_BYTES[info], "big")


arguments = st.one_of(
    st.sampled_from(_BOUNDARIES),
    st.integers(0, 23),
    st.integers(24, 2**16),
    st.integers(2**16, 2**32),
    st.integers(2**32, 2**64 - 1),
)


@st.composite
def integers(draw) -> bytes:
    major_type = draw(st.sampled_from([0, 1]))
    event("negative integer" if major_type else "unsigned integer")
    return draw(head(major_type, draw(arguments)))


@st.composite
def definite_bytes(draw) -> bytes:
    content = draw(st.binary(max_size=40))
    return draw(head(2, len(content))) + content


@st.composite
def definite_text(draw) -> bytes:
    content = draw(st.text(max_size=12)).encode("utf-8")
    return draw(head(3, len(content))) + content


@st.composite
def strings(draw) -> bytes:
    kind = draw(st.sampled_from(["bytes", "text"]))
    chunk = definite_bytes() if kind == "bytes" else definite_text()
    if not draw(st.booleans()):
        event(f"definite {kind} string")
        return draw(chunk)
    chunks = draw(st.lists(chunk, max_size=3))
    event(f"indefinite-length {kind} string" + (" with no chunks" if not chunks else ""))
    return bytes([0x5F if kind == "bytes" else 0x7F]) + b"".join(chunks) + b"\xff"


@st.composite
def simple_values(draw) -> bytes:
    if draw(st.booleans()):
        event("false, true, null or undefined")
        return bytes([draw(st.sampled_from([0xF4, 0xF5, 0xF6, 0xF7]))])
    value = draw(st.one_of(st.integers(0, 19), st.integers(32, 255)))
    event("simple value")
    return bytes([0xE0 | value]) if value < 24 else bytes([0xF8, value])


_FLOAT_FORMATS = {0xF9: ">e", 0xFA: ">f", 0xFB: ">d"}
_NOTABLE_FLOATS = [
    "f97e00", "f97e01", "f9fe00", "f97c00", "f9fc00", "f98000", "f90000", "f90001", "f93c00",
    "fa7fc00000", "fa7fc00001", "faffc00000", "fa7f800000", "fa00000001", "fa3f800000",
    "fb7ff8000000000000", "fb7ff8000000000001", "fbfff8000000000000", "fb0000000000000001", "fb3ff0000000000000",
]


@st.composite
def floats(draw) -> bytes:
    if draw(st.booleans()):
        item = bytes.fromhex(draw(st.sampled_from(_NOTABLE_FLOATS)))
    else:
        initial = draw(st.sampled_from(sorted(_FLOAT_FORMATS)))
        item = bytes([initial]) + draw(st.binary(min_size=struct.calcsize(_FLOAT_FORMATS[initial]), max_size=8).map(
            lambda bits, initial=initial: bits[: struct.calcsize(_FLOAT_FORMATS[initial])]))
    value = struct.unpack(_FLOAT_FORMATS[item[0]], item[1:])[0]
    event(f"{ {0xF9: 'half', 0xFA: 'single', 0xFB: 'double'}[item[0]] }-precision float")
    if math.isnan(value):
        quiet = {0xF9: "7e00", 0xFA: "7fc00000", 0xFB: "7ff8000000000000"}[item[0]]
        event("NaN" if item[1:].hex() == quiet else "NaN with a payload or sign")
    elif math.isinf(value):
        event("infinity")
    elif value == 0:
        event("negative zero" if math.copysign(1.0, value) < 0 else "zero")
    return item


leaves = st.one_of(integers(), strings(), simple_values(), floats())

# Keys drawn from a handful of items (1, "a", h'01', 1.0 at two widths, an
# indefinite "a", false) come round again, so maps repeat keys.
_KEY_POOL = ["01", "6161", "4101", "f93c00", "fa3f800000", "7f6161ff", "f4", "20", "1801"]
keys = st.one_of(st.sampled_from(_KEY_POOL).map(bytes.fromhex), leaves)


@st.composite
def arrays(draw, children) -> bytes:
    items = draw(st.lists(children, max_size=4))
    if draw(st.booleans()):
        event("indefinite-length array")
        return b"\x9f" + b"".join(items) + b"\xff"
    event("array")
    return draw(head(4, len(items))) + b"".join(items)


@st.composite
def maps(draw, children) -> bytes:
    entries = draw(st.lists(st.tuples(keys, children), max_size=4))
    if len({key for key, _value in entries}) < len(entries):
        event("map with a duplicate key")
    body = b"".join(key + value for key, value in entries)
    if draw(st.booleans()):
        event("indefinite-length map")
        return b"\xbf" + body + b"\xff"
    event("map")
    return draw(head(5, len(entries))) + body


@st.composite
def tags(draw, children) -> bytes:
    content = draw(children)
    if content[0] >> 5 == 6:
        event("tag inside a tag")
    event("tag")
    return draw(head(6, draw(arguments))) + content


items = st.recursive(leaves, lambda children: st.one_of(arrays(children), maps(children), tags(children)), max_leaves=12)
