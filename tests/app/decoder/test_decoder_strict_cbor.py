"""The decoder reads CBOR with one strict parser.

Input that is not well-formed CBOR (RFC 8949) fails, saying where. Input that is
well-formed decodes to what it says -- null is null, a float is its value --
and bytes after the item are reported, never decoded as more items or dropped.
"""
from __future__ import annotations

import hashlib
from typing import Any

import pytest

from fido2 import cbor


def _decode(hex_text: str) -> dict[str, Any]:
    decode_module = pytest.importorskip("server.app.decoder.decode")
    return decode_module.decode_payload_text(hex_text)


def _decode_error(hex_text: str) -> Any:
    decode_module = pytest.importorskip("server.app.decoder.decode")
    with pytest.raises(ValueError) as caught:
        decode_module.decode_payload_text(hex_text)
    return caught.value


@pytest.mark.parametrize(
    ("hex_text", "offset", "path", "reason"),
    [
        ("48aabb", 0, "$", "byte string declares 8 bytes; 2 remain"),
        ("8a01", 2, "$[1]", "array declares 10 items; the data ends after 1"),
        ("1e", 0, "$", "additional information 30 is reserved"),
        ("a20102", 3, "$", "map declares 2 entries; the data ends after 1"),
        ("a2010203", 3, "${3}", "map key 3 has no value"),
        ("a1016261", 2, "${1}", "text string declares 2 bytes; 1 remain"),
        ("19ff", 0, "$", "the head needs 2 more bytes; 1 remain"),
        ("81ff", 1, "$[0]", "a break byte (0xff) outside an indefinite-length item"),
        ("9f01", 2, "$", "indefinite-length array has no break byte"),
        ("fa3fc0", 0, "$", "a single-precision float needs 4 bytes"),
        ("f818", 0, "$", "simple value 24 must be written in one byte"),
        ("5f4101610200ff", 3, "$<chunk 1>", "a chunk of an indefinite-length byte string must be"),
        ("62c328", 0, "$", "text string is not valid UTF-8"),
    ],
)
def test_input_that_is_not_well_formed_fails_with_its_location(hex_text, offset, path, reason):
    error = _decode_error(hex_text)

    assert error.offset == offset
    assert error.path == path
    assert reason in str(error)
    assert str(error).startswith(f"Not well-formed CBOR at offset {offset} ({path}): ")


def test_offsets_count_the_ctap_prefix_byte():
    # A SUCCESS status byte, then a byte string that declares 8 bytes and has 2.
    error = _decode_error("0048aabb")

    assert error.offset == 1


def test_the_decode_endpoint_returns_the_location_of_a_parse_error(client):
    response = client.post("/api/codec", json={"payload": "8a01", "mode": "decode"})

    assert response.status_code == 422
    body = response.get_json()
    assert body["offset"] == 2
    assert body["path"] == "$[1]"
    assert "array declares 10 items" in body["error"]


def test_nesting_deeper_than_the_limit_fails_instead_of_exhausting_the_stack():
    error = _decode_error("a101" * 100 + "00")

    assert "nested more than 64 deep" in str(error)


@pytest.mark.parametrize(
    ("hex_text", "expected"),
    [
        ("f6", None),
        ("f4", False),
        ("f5", True),
        ("f7", {"diagnostic": "undefined"}),
        ("81f0", [{"diagnostic": "simple(16)"}]),
        ("f820", {"diagnostic": "simple(32)"}),
        ("f93c00", 1.0),
        ("fa3fc00000", 1.5),
        ("fb3ff8000000000000", 1.5),
        ("f97e00", {"diagnostic": "NaN"}),
        ("f9fc00", {"diagnostic": "-Infinity"}),
        ("8201f6", [1, None]),
        ("83f6f7f5", [None, {"diagnostic": "undefined"}, True]),
    ],
)
def test_simple_values_and_floats_decode_to_what_they_are(hex_text, expected):
    assert _decode(hex_text)["data"]["decodedValue"] == expected


def test_a_float_consumes_its_payload_so_the_next_item_is_read_in_place():
    # [1.5, 7]. fido2.cbor alone reads the float as False and its four payload
    # bytes as the next items; the old chain only got this right by falling
    # through to cbor2 when fido2.cbor then choked.
    assert _decode("82fa3fc0000007")["data"]["decodedValue"] == [1.5, 7]


def test_keys_that_json_would_collapse_stay_distinct():
    # {1: 0, true: 1, 1.0: 2, null: 3}
    result = _decode("a40100f501f93c0002f603")

    assert result["data"]["decodedValue"] == {"1": 0, "true": 1, "1.0": 2, "null": 3}


def test_bytes_after_the_item_are_reported_and_not_read_as_more_items():
    result = _decode("a10102deadbeef")

    assert result["data"]["decodedValue"] == {"1": 2}
    assert result["malformed"] == ["Trailing 4 byte(s) after CBOR payload."]


def test_a_second_item_after_the_first_is_trailing_bytes_not_a_sequence():
    # "a", then 6a 6b: one item and two bytes after it.
    result = _decode("61616a6b")

    assert result["data"]["decodedValue"] == "a"
    assert result["malformed"] == ["Trailing 2 byte(s) after CBOR payload."]


def test_bytes_after_a_make_credential_response_are_reported_with_the_response():
    auth_data = hashlib.sha256(b"example.com").digest() + b"\x01" + (5).to_bytes(4, "big")
    body = cbor.encode({1: "packed", 2: auth_data, 3: {"alg": -7, "sig": b"\x30\x06"}})

    result = _decode((b"\x00" + body + b"\xde\xad\xbe\xef").hex())

    assert result["type"] == "CBOR (SUCCESS status; MakeCredential response)"
    assert result["data"]["ctap"]["trailingBytesHex"] == "deadbeef"
    assert result["data"]["ctap"]["payloadLength"] == len(body)
    assert result["malformed"] == ["Trailing 4 byte(s) after CBOR payload."]


def test_zero_padding_after_a_response_is_reported_too():
    result = _decode("00a10102" + "00" * 8)

    assert result["data"]["ctap"]["ignoredPaddingBytes"] == 8
    assert result["malformed"] == ["Trailing 8 byte(s) after CBOR payload (all 0x00/0xff: HID report padding?)."]


def test_lenient_parsing_keeps_what_is_there_and_says_what_it_stepped_over():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    node, end, skipped = decode_module.decode_item(bytes.fromhex("48aabb"), lenient=True)

    assert node["hex"] == "aabb"
    assert node["truncated"] is True
    assert node["declaredLength"] == 8
    assert end == 3
    assert skipped == [
        {
            "code": "truncated",
            "category": "skipped",
            "offset": 0,
            "path": "$",
            "message": "byte string declares 8 bytes; 2 remain",
        }
    ]


def test_lenient_parsing_closes_a_short_container_and_steps_over_a_reserved_byte():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    node, end, skipped = decode_module.decode_item(bytes.fromhex("831e01"), lenient=True)

    assert decode_module._structure_to_value(node) == [decode_module.CborDiagnostic("invalid(h'1e')"), 1]
    assert end == 3
    assert [(entry["code"], entry["offset"], entry["path"]) for entry in skipped] == [
        ("reserved-additional-info", 1, "$[0]"),
        ("truncated", 3, "$[2]"),
    ]


def test_strict_parsing_never_records_skips():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    node, end, skipped = decode_module.decode_item(bytes.fromhex("a10102"))

    assert skipped == []
    assert (node["offset"], node["end"], end) == (0, 3, 3)
