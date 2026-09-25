"""Hypothesis strategies for CTAP messages in CTAP2 canonical form, for the CTAP view round trip.

makeCredential and getAssertion requests and responses, and getInfo responses
(CTAP 2.2 sections 6.1, 6.2 and 6.4), each drawn as its members, with and
without a command or status byte before it and bytes after it. The members
reach what a view has to carry exactly: bytes beside text that looks like hex
(SafetyNet's ``ver`` digits), null members (a null user icon), integer keys
inside extensions (hmac-secret), text spelled like a typed value, floats, tags,
simple values and undefined in open positions, authenticator data with and
without attested credential data and extensions, and the real attestation
statements of every format (``real_vectors``).

The bytes are written here, by a CTAP2-canonical writer of this module's own,
not by the server's encoder: a writer shared by both sides would prove nothing.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any

from hypothesis import event
from hypothesis import strategies as st

from .decoder import real_vectors


@dataclass(frozen=True)
class Tag:
    number: int
    value: Any


@dataclass(frozen=True)
class Simple:
    number: int


class _Undefined:
    pass


UNDEFINED = _Undefined()


# -- the writer ------------------------------------------------------------------


def _head(major: int, argument: int) -> bytes:
    if argument < 24:
        return bytes([major << 5 | argument])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < 1 << (8 * width):
            return bytes([major << 5 | info]) + argument.to_bytes(width, "big")
    raise ValueError(argument)


def _float(value: float) -> bytes:
    if math.isnan(value):
        return b"\xf9\x7e\x00"
    for prefix, fmt in ((b"\xf9", ">e"), (b"\xfa", ">f")):
        try:
            packed = struct.pack(fmt, value)
        except OverflowError:
            continue
        if struct.unpack(fmt, packed)[0] == value:
            return prefix + packed
    return b"\xfb" + struct.pack(">d", value)


def write(value: Any) -> bytes:
    """``value`` in CTAP2 canonical CBOR: shortest heads, definite lengths, map keys in CTAP2 order."""

    if value is None:
        return b"\xf6"
    if value is True or value is False:
        return b"\xf5" if value else b"\xf4"
    if value is UNDEFINED:
        return b"\xf7"
    if isinstance(value, Simple):
        return bytes([0xE0 | value.number]) if value.number < 24 else b"\xf8" + bytes([value.number])
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, float):
        return _float(value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(write(item) for item in value)
    if isinstance(value, dict):
        entries = sorted(((write(key), write(item)) for key, item in value.items()), key=lambda e: (e[0][0] >> 5, len(e[0]), e[0]))
        return _head(5, len(entries)) + b"".join(key + item for key, item in entries)
    if isinstance(value, Tag):
        return _head(6, value.number) + write(value.value)
    raise TypeError(type(value))


# -- values ------------------------------------------------------------------------

# Text a view could take for something else: hex digits, typed spellings, labels.
def _noted(strategy, label: str):
    """``strategy``, counting each value it gives as ``label`` in the test's statistics."""

    def note(value: Any) -> Any:
        event(label)
        return value

    return strategy.map(note)


_AWKWARD_TEXT = ["", "01", "abcd", "14574037", "h'01' (bytes)", "1 (fmt)", "a #2", "1.5 (float)", '"x" (text)', "null"]
texts = st.one_of(
    st.text(max_size=10),
    _noted(st.sampled_from(_AWKWARD_TEXT), "text spelled like bytes, a typed value or a label"),
    _noted(st.from_regex(r"[0-9a-f]{2,8}", fullmatch=True), "text spelled like bytes"),
)
integers = st.one_of(st.integers(-24, 24), st.integers(-(2**64), 2**64 - 1))
byte_strings = st.binary(max_size=24)
scalars = st.one_of(
    integers,
    texts,
    byte_strings,
    st.booleans(),
    st.none(),
    _noted(st.floats(allow_nan=False, allow_infinity=True, width=64), "a float"),
    _noted(st.just(math.nan), "NaN"),
    _noted(st.builds(Simple, st.one_of(st.integers(0, 19), st.integers(32, 255))), "a simple value"),
    _noted(st.just(UNDEFINED), "undefined"),
)
map_keys = st.one_of(integers, texts, byte_strings)
# An rpId or fmt: a message's shape needs one that is not blank ("compound" takes an array).
_names = texts.map(lambda text: text if text.strip() and text != "compound" else "example.com")


def _open(children):
    return st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(map_keys, children, max_size=3),
        _noted(st.builds(Tag, st.integers(0, 2**32), children), "a tag"),
    )


open_values = st.recursive(scalars, _open, max_leaves=6)


# -- members -------------------------------------------------------------------------

_COSE_KEY = {1: 2, 3: -7, -1: 1, -2: bytes(range(32)), -3: bytes(range(32, 64))}


@st.composite
def authenticator_data(draw) -> bytes:
    flags = draw(st.sampled_from([0x01, 0x05, 0x04, 0x1D]))
    body = draw(st.binary(min_size=32, max_size=32)) + b"" + draw(st.integers(0, 2**32 - 1)).to_bytes(4, "big")
    attested = draw(st.booleans())
    extensions = draw(st.booleans())
    tail = b""
    if attested:
        flags |= 0x40
        credential_id = draw(st.binary(max_size=40))
        key = draw(st.one_of(st.just(_COSE_KEY), st.dictionaries(st.integers(-4, 4), open_values, min_size=1, max_size=3)))
        tail += draw(st.binary(min_size=16, max_size=16)) + len(credential_id).to_bytes(2, "big") + credential_id + write(key)
        event("authData with attested credential data")
    if extensions:
        flags |= 0x80
        tail += write(draw(st.dictionaries(texts, open_values, min_size=1, max_size=3)))
        event("authData with extensions")
    if draw(st.integers(0, 9)) == 0:
        tail += draw(st.binary(min_size=1, max_size=4))
        event("authData with bytes after what its flags describe")
    return body[:32] + bytes([flags]) + body[32:] + tail


def _optional(draw, members: dict, key: int, strategy) -> None:
    if draw(st.booleans()):
        members[key] = draw(strategy)


def _unknown_members(draw, members: dict) -> None:
    # A member CTAP 2.2 does not define, and a key that is no integer: shown and written back.
    if draw(st.integers(0, 4)) == 0:
        members[draw(st.integers(40, 200))] = draw(open_values)
        event("a member CTAP 2.2 does not define")
    if draw(st.integers(0, 6)) == 0:
        members[draw(st.one_of(texts, byte_strings))] = draw(open_values)
        event("a key that is no integer")


descriptors = st.fixed_dictionaries(
    {"id": byte_strings, "type": st.just("public-key")},
    optional={"transports": st.lists(st.sampled_from(["usb", "nfc", "ble", "internal"]), max_size=2)},
)
users = st.fixed_dictionaries(
    {"id": byte_strings},
    optional={"name": texts, "displayName": texts, "icon": st.one_of(_noted(st.none(), "a null user icon"), texts)},
)
_HMAC_SECRET = _noted(
    st.fixed_dictionaries({1: st.just(_COSE_KEY), 2: st.binary(min_size=32, max_size=32), 3: st.binary(min_size=16, max_size=16)}),
    "hmac-secret, its members numbered",
)
extensions = st.dictionaries(
    st.sampled_from(["hmac-secret", "credProtect", "credBlob", "largeBlobKey", "minPinLength"]),
    st.one_of(_HMAC_SECRET, open_values),
    max_size=3,
)
options = st.dictionaries(st.sampled_from(["rk", "up", "uv", "plat", "clientPin"]), st.booleans(), max_size=3)


@st.composite
def make_credential_request(draw) -> dict:
    members: dict[Any, Any] = {
        1: draw(st.binary(min_size=32, max_size=32)),
        2: draw(st.fixed_dictionaries({"id": texts}, optional={"name": texts})),
        3: draw(users),
        4: draw(st.lists(st.fixed_dictionaries({"alg": integers, "type": st.just("public-key")}), min_size=1, max_size=3)),
    }
    _optional(draw, members, 5, st.lists(descriptors, max_size=2))
    _optional(draw, members, 6, extensions)
    _optional(draw, members, 7, options)
    _optional(draw, members, 8, byte_strings)
    _optional(draw, members, 9, st.integers(1, 2))
    _optional(draw, members, 10, st.integers(1, 2))
    _optional(draw, members, 11, st.lists(texts, max_size=2))
    _unknown_members(draw, members)
    return members


@st.composite
def get_assertion_request(draw) -> dict:
    members: dict[Any, Any] = {1: draw(_names), 2: draw(st.binary(min_size=32, max_size=32))}
    _optional(draw, members, 3, st.lists(descriptors, max_size=2))
    _optional(draw, members, 4, extensions)
    _optional(draw, members, 5, options)
    _optional(draw, members, 6, byte_strings)
    _optional(draw, members, 7, st.integers(1, 2))
    _unknown_members(draw, members)
    return members


# Real statements of every format, and open ones: SafetyNet's ver is digits, text.
_STATEMENTS = [
    ("packed", real_vectors.PACKED_ATT_STMT),
    ("tpm", real_vectors.TPM_WINDOWS_HELLO_ATT_STMT),
    ("android-safetynet", real_vectors.ANDROID_SAFETYNET_ATT_STMT),
    ("fido-u2f", real_vectors.FIDO_U2F_ATT_STMT),
    ("apple", real_vectors.APPLE_ATT_STMT),
    ("none", real_vectors.NONE_ATT_STMT),
]


@st.composite
def attestation_statement(draw) -> tuple[str, Any]:
    kind = draw(st.integers(0, 4))
    if kind < 3:
        fmt, statement = draw(st.sampled_from(_STATEMENTS))
        event(f"attStmt: {fmt}")
        return fmt, statement
    if kind == 3:
        # x5c entries a certificate reader cannot read, and one that is no byte string.
        event("attStmt: x5c with entries that are no certificate")
        return "packed", {"alg": -7, "sig": draw(byte_strings), "x5c": draw(st.lists(st.one_of(byte_strings, integers), max_size=2))}
    event("attStmt: an open map")
    return draw(_names), draw(st.dictionaries(texts, open_values, max_size=3))


@st.composite
def make_credential_response(draw) -> dict:
    fmt, statement = draw(attestation_statement())
    members: dict[Any, Any] = {1: fmt, 2: draw(authenticator_data()), 3: statement}
    _optional(draw, members, 4, st.booleans())
    _optional(draw, members, 5, st.binary(min_size=32, max_size=32))
    _optional(draw, members, 6, st.dictionaries(texts, open_values, max_size=2))
    _unknown_members(draw, members)
    return members


@st.composite
def get_assertion_response(draw) -> dict:
    members: dict[Any, Any] = {2: draw(authenticator_data()), 3: draw(byte_strings)}
    _optional(draw, members, 1, descriptors)
    _optional(draw, members, 4, users)
    _optional(draw, members, 5, st.integers(1, 5))
    _optional(draw, members, 6, st.booleans())
    _optional(draw, members, 7, st.binary(min_size=32, max_size=32))
    _optional(draw, members, 8, st.dictionaries(texts, open_values, max_size=2))
    _unknown_members(draw, members)
    return members


@st.composite
def get_info_response(draw) -> dict:
    members: dict[Any, Any] = {
        1: draw(st.lists(st.sampled_from(["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_2"]), min_size=1, max_size=3)),
        3: draw(st.binary(min_size=16, max_size=16)),
    }
    _optional(draw, members, 2, st.lists(texts, max_size=3))
    _optional(draw, members, 4, st.dictionaries(texts, st.booleans(), max_size=4))
    _optional(draw, members, 5, st.integers(0, 2**16))
    _optional(draw, members, 6, st.lists(st.integers(1, 2), max_size=2))
    _optional(draw, members, 9, st.lists(texts, max_size=2))
    _optional(draw, members, 10, st.lists(st.fixed_dictionaries({"alg": integers, "type": st.just("public-key")}), max_size=3))
    _optional(draw, members, 14, st.integers(0, 2**32))
    _optional(draw, members, 18, st.integers(0, 2**32 - 1))
    _optional(draw, members, 19, st.dictionaries(texts, st.integers(0, 6), max_size=2))
    _optional(draw, members, 25, byte_strings)
    _optional(draw, members, 28, byte_strings)
    _unknown_members(draw, members)
    return members


# The CTAP byte that may come before each message.
MESSAGES = {
    "makeCredentialRequest": (make_credential_request(), 0x01),
    "getAssertionRequest": (get_assertion_request(), 0x02),
    "makeCredentialResponse": (make_credential_response(), 0x00),
    "getAssertionResponse": (get_assertion_response(), 0x00),
    "getInfoResponse": (get_info_response(), 0x00),
}


@st.composite
def messages(draw, message: str) -> bytes:
    """One ``message`` in CTAP2 canonical form, perhaps after its CTAP byte, perhaps with bytes after it."""

    strategy, code = MESSAGES[message]
    body = write(draw(strategy))
    framed = draw(st.booleans())
    prefix = bytes([code]) if framed else b""
    event(f"{message}, {'after its CTAP byte' if framed else 'with no CTAP byte'}")
    trailing = b""
    if draw(st.integers(0, 4)) == 0:
        trailing = draw(st.one_of(st.binary(min_size=1, max_size=4), st.sampled_from([b"\x00\x00", b"\xff"])))
        event("bytes after the message")
    return prefix + body + trailing
