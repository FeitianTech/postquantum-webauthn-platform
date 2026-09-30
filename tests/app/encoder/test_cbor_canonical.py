"""``decoder.cbor_canonical``: the one writer of CBOR from values, in CTAP2 canonical form."""
from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import cbor2
import pytest

from server.app.decoder import cbor_canonical, values


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        (True, "f5"),
        (None, "f6"),
        (cbor2.undefined, "f7"),
        ([1, 2], "820102"),
        (b"AB", "424142"),
        (memoryview(b"AB"), "424142"),
        ("ok", "626f6b"),
        (-1, "20"),
        (cbor2.CBORSimpleValue(5), "e5"),
        (cbor2.CBORSimpleValue(32), "f820"),
        (cbor2.CBORTag(1, 2), "c102"),
    ],
)
def test_each_kind_of_value_has_one_encoding(value, encoded):
    assert cbor_canonical._canonical_cbor_dumps(value).hex() == encoded


@pytest.mark.parametrize(
    ("value", "encoded"),
    [(23, "17"), (24, "1818"), (255, "18ff"), (256, "190100"), (65536, "1a00010000"), (2**32, "1b0000000100000000")],
)
def test_an_integer_takes_the_shortest_head_that_holds_it(value, encoded):
    assert cbor_canonical._canonical_cbor_dumps(value).hex() == encoded


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        (1.5, "f93e00"),
        (-0.0, "f98000"),
        (float("inf"), "f97c00"),
        (float("nan"), "f97e00"),
        (100000.0, "fa47c35000"),
        (1e40, "fb483d6329f1c35ca5"),
    ],
)
def test_a_float_takes_the_shortest_width_that_holds_it_exactly(value, encoded):
    assert cbor_canonical._canonical_cbor_dumps(value).hex() == encoded


@pytest.mark.parametrize(
    ("value", "error"),
    [
        (Decimal("1.5"), "No canonical CBOR encoding for Decimal values"),
        (2**64, "CBOR integers exceeding 64 bits are not supported"),
        # Two keys that spell the same CBOR key.
        ({1: "a", values.CborDiagnostic("1"): "b"}, "Duplicate CBOR map key"),
    ],
)
def test_what_has_no_canonical_encoding_is_refused(value, error):
    with pytest.raises(ValueError, match=error):
        cbor_canonical._canonical_cbor_dumps(value)


def test_the_structure_shown_follows_the_encodings_key_order():
    assert list(cbor_canonical._canonicalize_cbor_structure({"": 0, 24: 0})) == [24, ""]
    assert cbor_canonical._canonicalize_cbor_structure(cbor2.CBORTag(42, [memoryview(b"ab")])) == cbor2.CBORTag(42, [b"ab"])


# What cbor2 will not construct -- a negative tag, a reserved or out-of-range simple
# value -- and a negative length only a direct call gives the encoder.


def test_a_tag_and_a_simple_value_are_checked_even_when_cbor2_did_not_make_them():
    encoder = cbor_canonical._CanonicalCBOREncoder()

    with pytest.raises(ValueError, match="CBOR tags must be non-negative integers"):
        encoder._encode_tag(SimpleNamespace(tag=-1, value=2))
    with pytest.raises(TypeError, match="must be an integer"):
        encoder._encode_cbor_simple_value(SimpleNamespace(value="x"))
    with pytest.raises(ValueError, match="between 0 and 255"):
        encoder._encode_cbor_simple_value(SimpleNamespace(value=999))
    with pytest.raises(ValueError, match="reserved"):
        encoder._encode_cbor_simple_value(SimpleNamespace(value=25))
    assert encoder._encode_simple(cbor2.CBORSimpleValue(16)) == b"\xf0"
    with pytest.raises(ValueError, match="lengths must be non-negative"):
        cbor_canonical._encode_major_type_with_length(2, -1)
