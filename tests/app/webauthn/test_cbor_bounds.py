"""``webauthn.cbor_bounds``: how deep a response's CBOR nests and how many items it holds,
read from its heads as fido2's decoder reads the same bytes."""
from __future__ import annotations

import base64

import pytest
from fido2 import cbor
from hypothesis import given, settings
from hypothesis import strategies as st

from server.app.webauthn import cbor_bounds
from server.app.webauthn.cbor_bounds import Walk
from tests.app import cbor_items
from tests.app.security.ceremony_helpers import Authenticator, b64u

UNLIMITED = {"max_depth": 10**9, "max_items": 10**9}


@pytest.mark.parametrize(
    ("hex_item", "walked"),
    [
        # Integers, both signs, at every argument width.
        ("17", Walk(1, 1, 1)),
        ("1818", Walk(2, 1, 1)),
        ("190100", Walk(3, 1, 1)),
        ("1a00010000", Walk(5, 1, 1)),
        ("1b0000000100000000", Walk(9, 1, 1)),
        ("38ff", Walk(2, 1, 1)),
        # Strings: their payload skipped, at a definite length or in chunks.
        ("43010203", Walk(4, 1, 1)),
        ("5818" + "00" * 24, Walk(26, 1, 1)),
        ("63616263", Walk(4, 1, 1)),
        ("5f41014102ff", Walk(6, 2, 3)),
        ("7fff", Walk(2, 1, 1)),
        # Arrays and maps, definite and indefinite, and tags.
        ("80", Walk(1, 1, 1)),
        ("a0", Walk(1, 1, 1)),
        ("820102", Walk(3, 2, 3)),
        ("a10102", Walk(3, 2, 3)),
        ("9f0102ff", Walk(4, 2, 3)),
        ("bf0102ff", Walk(4, 2, 3)),
        ("829fff01", Walk(4, 2, 3)),
        ("9f9fffff", Walk(4, 2, 2)),
        ("c100", Walk(2, 2, 2)),
        ("d818c100", Walk(4, 3, 3)),
        # Major type 7 as fido2 reads it: its first byte alone, whatever follows.
        ("f4", Walk(1, 1, 1)),
        ("f820", Walk(1, 1, 1)),
        ("fb3ff0000000000000", Walk(1, 1, 1)),
        ("ff", Walk(1, 1, 1)),
        ("82f90000", Walk(3, 2, 3)),
    ],
)
def test_an_item_is_walked_to_its_end_through_its_heads(hex_item, walked):
    data = bytes.fromhex(hex_item)

    assert cbor_bounds.walk(data + b"\x00\x00") == walked


def test_an_item_is_walked_from_an_offset():
    assert cbor_bounds.walk(bytes.fromhex("ffff820102"), 2) == Walk(5, 2, 3)


@pytest.mark.parametrize(
    ("hex_item", "walked"),
    [
        ("", Walk(None, 0, 0)),
        ("18", Walk(None, 1, 1)),
        ("1901", Walk(None, 1, 1)),
        ("1c", Walk(None, 1, 1)),
        ("1f", Walk(None, 1, 1)),
        ("df00", Walk(None, 1, 1)),
        ("4301", Walk(None, 1, 1)),
        ("8201", Walk(None, 2, 2)),
        ("9f01", Walk(None, 2, 2)),
        ("c1", Walk(None, 1, 1)),
        # What came before an item the walk cannot follow still counts.
        ("8401025b", Walk(None, 2, 4)),
    ],
)
def test_what_the_walk_cannot_follow_ends_it_unknown(hex_item, walked):
    assert cbor_bounds.walk(bytes.fromhex(hex_item)) == walked


def test_the_walk_stops_once_past_a_cap():
    deep = b"\x81" * (cbor_bounds.MAX_DEPTH + 10) + b"\x00"
    many = b"\x99\x01\xf4" + b"\xa0" * 500

    assert cbor_bounds.walk(deep) == Walk(None, cbor_bounds.MAX_DEPTH + 1, cbor_bounds.MAX_DEPTH + 1)
    assert cbor_bounds.walk(many) == Walk(None, 2, cbor_bounds.MAX_ITEMS + 1)


def test_a_value_nested_a_hundred_thousand_deep_is_walked_without_recursing():
    data = b"\x81" * 100_000 + b"\x00"

    assert cbor_bounds.walk(data, **UNLIMITED) == Walk(100_001, 100_001, 100_001)


def _depth(value) -> int:
    if isinstance(value, list):
        return 1 + max(map(_depth, value), default=0)
    if isinstance(value, dict):
        return 1 + max((max(_depth(k), _depth(v)) for k, v in value.items()), default=0)
    return 1


def _items(value) -> int:
    if isinstance(value, list):
        return 1 + sum(map(_items, value))
    if isinstance(value, dict):
        return 1 + sum(_items(k) + _items(v) for k, v in value.items())
    return 1


_SCALARS = st.one_of(
    st.integers(-(2**64), 2**64 - 1), st.booleans(), st.binary(max_size=300), st.text(max_size=30)
)
_VALUES = st.recursive(
    _SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.one_of(st.integers(-1000, 1000), st.text(max_size=8)), children, max_size=5),
    ),
    max_leaves=40,
)


@settings(max_examples=500)
@given(_VALUES, st.binary(max_size=4))
def test_the_walk_ends_where_fido2s_decode_does_and_counts_what_it_decodes(value, trailing):
    data = cbor.encode(value) + trailing
    decoded, rest = cbor.decode_from(data)

    assert cbor_bounds.walk(data, **UNLIMITED) == Walk(len(data) - len(rest), _depth(decoded), _items(decoded))


@settings(max_examples=1500)
@given(cbor_items.items)
def test_whatever_fido2_decodes_the_walk_has_read_all_of(data):
    try:
        decoded, rest = cbor.decode_from(data)
    except Exception:
        return
    walked = cbor_bounds.walk(data, **UNLIMITED)

    # fido2 reads a string longer than what is left as the rest; the walk ends unknown there.
    assert walked.end == len(data) - len(rest) or (walked.end is None and not rest)
    # A map's repeated key is decoded once, and counted by the walk each time.
    assert walked.depth >= _depth(decoded)
    assert walked.items >= _items(decoded)


# -- the members fido2 reads --------------------------------------------------

DEEP = b"\x81" * (cbor_bounds.MAX_DEPTH + 1) + b"\x00"
MANY = b"\x99\x01\x91" + b"\xa0" * (cbor_bounds.MAX_ITEMS + 1)


def _auth_data(*, key: bytes | None = None, extensions: bytes | None = None) -> bytes:
    authenticator = Authenticator()
    data = bytearray(authenticator.authenticator_data(include_credential=False))
    if key is not None:
        data[32] |= 0x40
        data += authenticator.aaguid + len(authenticator.credential_id).to_bytes(2, "big") + authenticator.credential_id + key
    if extensions is not None:
        data[32] |= 0x80
        data += extensions
    return bytes(data)


def _registration(attestation_object) -> dict:
    return {"response": {"attestationObject": attestation_object}}


def _assertion(auth_data) -> dict:
    return {"response": {"authenticatorData": auth_data}}


KEY = Authenticator().cose_key_bytes


@pytest.mark.parametrize(
    ("auth_data", "excess"),
    [
        (_auth_data(key=KEY), None),
        (_auth_data(key=KEY, extensions=cbor.encode({"credProtect": 3})), None),
        (_auth_data(key=DEEP), cbor_bounds.DEPTH),
        (_auth_data(key=MANY), cbor_bounds.ITEMS),
        (_auth_data(key=KEY, extensions=DEEP), cbor_bounds.DEPTH),
        (_auth_data(extensions=MANY), cbor_bounds.ITEMS),
        # A key the walk cannot follow ends it, as fido2's read ends there.
        (_auth_data(key=b"\x1c", extensions=DEEP), None),
        (_auth_data(key=b"\x81" * 60), cbor_bounds.DEPTH),
        # Too short to hold what its flags say: fido2 refuses it unread.
        (_auth_data()[:36], None),
        (_auth_data(key=b"")[:50], None),
    ],
)
def test_an_assertions_authenticator_data_is_walked_where_its_flags_say_it_holds_cbor(auth_data, excess):
    assert cbor_bounds.assertion_excess(_assertion(b64u(auth_data))) == excess


def test_a_member_is_read_into_bytes_as_fido2_reads_it():
    auth_data = _auth_data(extensions=DEEP)
    encoded = b64u(auth_data)
    lenient = encoded[:10] + "!\n !" + encoded[10:]
    standard = base64.b64encode(auth_data).decode().rstrip("=")

    assert cbor_bounds.assertion_excess(_assertion(lenient)) == cbor_bounds.DEPTH
    assert cbor_bounds.assertion_excess(_assertion(standard)) == cbor_bounds.DEPTH
    assert cbor_bounds.assertion_excess(_assertion(list(auth_data))) == cbor_bounds.DEPTH
    for unread in (None, 5, {"a": 1}, [256], "a", "é"):
        assert cbor_bounds.assertion_excess(_assertion(unread)) is None
    assert cbor_bounds.assertion_excess({"response": "not a mapping"}) is None
    assert cbor_bounds.assertion_excess(None) is None


def _attestation_object(*members: tuple[bytes, bytes]) -> bytes:
    return bytes([0xA0 | len(members)]) + b"".join(key + value for key, value in members)


def _text(value: str) -> bytes:
    return cbor.encode(value)


def _bytes_head(length: int) -> bytes:
    return b"\x5a" + length.to_bytes(4, "big")


FMT = (_text("fmt"), _text("none"))
STATEMENT = (_text("attStmt"), b"\xa0")
GOOD = cbor.encode(_auth_data(key=KEY))
HOSTILE_DATA = _auth_data(key=KEY, extensions=DEEP)
HOSTILE = cbor.encode(HOSTILE_DATA)


@pytest.mark.parametrize(
    ("attestation_object", "excess"),
    [
        (_attestation_object(FMT, STATEMENT, (_text("authData"), GOOD)), None),
        (_attestation_object(FMT, STATEMENT, (_text("authData"), HOSTILE)), cbor_bounds.DEPTH),
        (_attestation_object(FMT, STATEMENT, (_text("authData"), GOOD), (_text("x"), DEEP)), cbor_bounds.DEPTH),
        (_attestation_object(FMT, STATEMENT, (_text("authData"), GOOD), (_text("x"), MANY)), cbor_bounds.ITEMS),
        # fido2's decode keeps a repeated key's last value.
        (_attestation_object((_text("authData"), HOSTILE), FMT, (_text("authData"), GOOD)), None),
        (_attestation_object((_text("authData"), GOOD), FMT, (_text("authData"), HOSTILE)), cbor_bounds.DEPTH),
        (_attestation_object((_text("authData"), HOSTILE), (_text("authData"), b"\x01")), None),
        # The key at another width of head is the same key to fido2.
        (_attestation_object(FMT, (b"\x78\x08authData", HOSTILE)), cbor_bounds.DEPTH),
        # A byte string longer than what is left is the rest to fido2.
        (_attestation_object(FMT, (_text("authData"), _bytes_head(2**31) + HOSTILE_DATA)), cbor_bounds.DEPTH),
        # What the walk cannot follow ends the search, as it ends fido2's decode.
        (_attestation_object(FMT, (_text("x"), b"\x1c"), (_text("authData"), HOSTILE)), None),
        (_attestation_object((b"\x1c", b"\x00"), (_text("authData"), HOSTILE)), None),
        # Not a map of definite length: fido2 finds no authData in it.
        (b"\x82" + HOSTILE + HOSTILE, None),
        (b"\xbf" + _text("authData") + HOSTILE + b"\xff", None),
        (b"", None),
    ],
)
def test_a_registrations_attestation_object_and_the_authenticator_data_inside_are_walked(attestation_object, excess):
    assert cbor_bounds.registration_excess(_registration(b64u(attestation_object))) == excess


def test_a_registration_without_an_attestation_object_fido2_reads_is_left_to_fido2():
    assert cbor_bounds.registration_excess(_registration("not base64url é")) is None
    assert cbor_bounds.registration_excess({}) is None
