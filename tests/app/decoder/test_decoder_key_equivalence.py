"""Two map keys are one key when RFC 8949 section 5.6.1 says so, however each was written.

The decoded value keeps one entry for them, and ``duplicate-map-key`` says so.
It used to fold some equivalent keys silently -- 1.0 at half and at single
width, a text key and its indefinite-length twin -- with no finding at all.
"""
from __future__ import annotations

import pytest

from server.app.decoder import decode_payload_text
from server.app.decoder.decode import cbor_parser, key_equivalence


def _decode(hex_text: str) -> dict:
    return decode_payload_text(hex_text.replace(" ", ""))


def _codes(result: dict) -> list[str]:
    return [finding["code"] for finding in result["findings"]]


@pytest.mark.parametrize(
    ("hex_text", "decoded"),
    [
        ("a2 f93c00 01 fa3f800000 02", {"1.0": 2}),  # 1.0, half and single precision
        ("a2 f98000 01 f90000 02", {"-0.0": 2}),  # -0.0 is 0.0
        ("a2 f97e00 01 fa7fc00000 02", {"NaN": 2}),  # one NaN significand at two widths
        ("a2 f97e00 01 f9fe00 02", {"NaN": 2}),  # the sign bit is not the significand
        ("a2 7f6161ff 01 6161 02", {"a": 2}),  # a text key and its chunked twin
        ("a2 5f4101ff 01 4101 02", {"01": 2}),  # a byte string key and its chunked twin
        ("a2 01 01 1801 02", {"1": 2}),  # one integer, two head widths
        ("a2 c1 01 01 d801 01 02", {"1(1)": 2}),  # one tag, two head widths
        ("a2 81f93c00 01 81fb3ff0000000000000 02", {"[1.0]": 2}),  # arrays item by item
        ("a2 a10102 01 a10102 02", {"{1: 2}": 2}),  # maps as sets of pairs
    ],
)
def test_equivalent_keys_are_one_entry_and_a_duplicate(hex_text, decoded):
    result = _decode(hex_text)

    assert result["data"]["decodedValue"] == decoded
    assert _codes(result).count("duplicate-map-key") == 1
    # A duplicate is not "out of order" after itself.
    assert "map-key-order" not in _codes(result)


@pytest.mark.parametrize(
    ("hex_text", "decoded"),
    [
        ("a2 01 01 f93c00 02", {"1": 1, "1.0": 2}),  # an integer is never a float
        ("a2 4131 01 6131 02", {"31": 1, "1": 2}),  # bytes are never text
        ("a2 f97e00 01 f97e01 02", {"NaN": 1, "float'7e01'": 2}),  # different significands
        ("a2 c1 01 01 c2 01 02", {"1(1)": 1, "2(1)": 2}),  # different tags
        ("a2 01 01 c1 01 02", {"1": 1, "1(1)": 2}),  # tagged is not untagged
        ("a2 f5 01 f4 02", {"true": 1, "false": 2}),
    ],
)
def test_keys_that_are_not_equivalent_stay_apart(hex_text, decoded):
    result = _decode(hex_text)

    assert result["data"]["decodedValue"] == decoded
    assert "duplicate-map-key" not in _codes(result)


def test_a_merged_key_counts_once_among_keys_json_would_spell_alike():
    # {1: "a", "1": "b", 1_0: "c"}: two keys, not three.
    result = _decode("a3 01 6161 6131 6162 1801 6163")

    assert result["data"]["decodedValue"] == {"1": "c", '"1" (text)': "b"}
    (collision,) = [finding for finding in result["findings"] if finding["code"] == "json-key-collision"]
    assert collision["keys"] == ["1", '"1" (text)']


def test_a_nan_node_without_its_bits_is_identified_by_the_bits_of_its_value():
    parsed, _end, _ = cbor_parser.decode_item(bytes.fromhex("fb7ff8000000000000"))
    built = {"majorType": 7, "type": "float", "precision": "half", "value": float("nan")}

    assert key_equivalence.identity(built) == key_equivalence.identity(parsed) == ("nan", 1 << 63)
