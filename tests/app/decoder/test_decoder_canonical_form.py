"""Every decode reports where the CBOR is not in CTAP2 canonical form.

The findings say what, where (the byte offset, counted from the first input
byte) and on which item (the path); they never change the decoded value.
"""
from __future__ import annotations

import hashlib
from typing import Any

import pytest

from fido2 import cbor


def _decode(hex_text: str) -> dict[str, Any]:
    decode_module = pytest.importorskip("server.app.decoder.decode")
    return decode_module.decode_payload_text(hex_text)


def _located(result: dict[str, Any]) -> list[tuple[str, int, str]]:
    return [(finding["code"], finding["offset"], finding["path"]) for finding in result["findings"]]


def test_a_duplicate_map_key_is_reported_with_both_offsets():
    # {1: 1, 1: 2}: the second entry used to replace the first without a word.
    result = _decode("a201010102")

    assert result["data"]["decodedValue"] == {"1": 2}
    assert _located(result) == [("duplicate-map-key", 3, "${1}")]
    assert result["findings"][0]["message"] == (
        "map key 1 appears twice (first at offset 1); the decoded value keeps this later entry"
    )
    assert result["findings"][0]["category"] == "canonical"


def test_a_non_shortest_integer_is_reported_where_it_is_written():
    # {1: 2} with the key written as 18 01.
    result = _decode("a1180102")

    assert result["data"]["decodedValue"] == {"1": 2}
    assert _located(result) == [("non-shortest-integer", 1, "${1}")]
    assert result["findings"][0]["message"] == (
        "integer 1 has a 2-byte head (18 01); CTAP2 requires the shortest, 1 byte"
    )


def test_an_indefinite_length_map_is_reported():
    result = _decode("bf0102ff")

    assert result["data"]["decodedValue"] == {"1": 2}
    assert _located(result) == [("indefinite-length", 0, "$")]


@pytest.mark.parametrize(
    ("hex_text", "located"),
    [
        # {2: 0, 1: 0}: the same major type and length, so bytewise.
        ("a202000100", [("map-key-order", 3, "${1}")]),
        # {"a": 0, 1: 0}: major type 3 before major type 0.
        ("a26161000100", [("map-key-order", 4, "${1}")]),
        # {24: 0, 5: 0}: 18 18 is longer than 05, so 5 sorts first.
        ("a21818000500", [("map-key-order", 4, "${5}")]),
        # {"b": 0, "a": 0}
        ("a26162006161 00".replace(" ", ""), [("map-key-order", 4, '${"a"}')]),
        # {-1: 0, 24: 0}: 18 18 (major 0) before 20 (major 1), whatever the lengths.
        ("a22000181800", [("map-key-order", 3, "${24}")]),
    ],
)
def test_map_keys_out_of_ctap2_order_are_reported(hex_text, located):
    assert _located(_decode(hex_text)) == located


def test_map_keys_in_ctap2_order_are_not_reported():
    # {5: 0, 24: 0, -1: 0, h'': 0, "": 0, "a": 0}
    assert _decode("a60500181800200040006000616100")["findings"] == []


def test_a_key_written_twice_in_different_lengths_is_one_key_twice():
    # {1: 0, 1: 0}, the second 1 written as 18 01.
    result = _decode("a2010018 0100".replace(" ", ""))

    assert _located(result) == [("non-shortest-integer", 3, "${1}"), ("duplicate-map-key", 3, "${1}")]


@pytest.mark.parametrize(
    ("hex_text", "code", "message"),
    [
        ("5801aa", "non-shortest-length", "byte string of length 1 has a 2-byte head (58 01)"),
        # (Hex made only of digits would be read as a JSON number.)
        ("7900017a", "non-shortest-length", "text string of length 1 has a 3-byte head (79 00 01)"),
        ("9801f6", "non-shortest-length", "array of length 1 has a 2-byte head (98 01)"),
        ("3a00000000", "non-shortest-integer", "integer -1 has a 5-byte head (3a 00 00 00 00)"),
        ("c101", "tag", "tag 1; CTAP2 canonical CBOR has no tags"),
        ("5f4161ff", "indefinite-length", "indefinite-length byte string; CTAP2 requires definite lengths"),
    ],
)
def test_other_canonical_form_violations_are_reported(hex_text, code, message):
    finding = _decode(hex_text)["findings"][0]

    assert finding["code"] == code
    assert finding["message"].startswith(message)


def test_findings_in_nested_items_carry_their_path():
    # {1: [0, {"x": 18 05}]}
    result = _decode("a101820 0a1617818 05".replace(" ", ""))

    assert _located(result) == [("non-shortest-integer", 7, '${1}[1]{"x"}')]


def test_findings_never_change_the_decoded_value():
    canonical = _decode("a2010203 04".replace(" ", ""))["data"]["decodedValue"]
    # The same map written with long heads, indefinite length and keys reversed.
    other = _decode("bf1803041801 02ff".replace(" ", ""))

    assert other["data"]["decodedValue"] == canonical
    assert {finding["code"] for finding in other["findings"]} == {
        "indefinite-length",
        "non-shortest-integer",
        "map-key-order",
    }


def test_findings_are_listed_in_byte_order_with_trailing_bytes_last():
    result = _decode("a2020001 00ff".replace(" ", ""))

    assert [finding["offset"] for finding in result["findings"]] == [3, 5]
    assert [finding["code"] for finding in result["findings"]] == ["map-key-order", "trailing-bytes"]
    trailing = result["findings"][1]
    assert (trailing["category"], trailing["length"], trailing["hex"]) == ("trailing", 1, "ff")


def test_malformed_lists_every_finding_message():
    result = _decode("a201010102")

    assert result["malformed"] == [finding["message"] for finding in result["findings"]]


def test_a_ctap_message_is_checked_with_offsets_counting_its_prefix_byte():
    # MAKE_CREDENTIAL, then {2: ..., 1: ...}: key 1 is out of order.
    rp = cbor.encode({"id": "example.com"})
    body = b"\xa2" + cbor.encode(2) + rp + cbor.encode(1) + cbor.encode(bytes(32))

    result = _decode((b"\x01" + body).hex())

    key_one_offset = 1 + 1 + 1 + len(rp)
    assert _located(result) == [("map-key-order", key_one_offset, "${1}")]


def test_an_attestation_object_is_checked_too():
    auth_data = hashlib.sha256(b"example.com").digest() + b"\x01" + (5).to_bytes(4, "big")
    # authData before fmt: "authData" is longer than "fmt", so it sorts after it.
    attestation = (
        b"\xa3"
        + cbor.encode("authData")
        + cbor.encode(auth_data)
        + cbor.encode("fmt")
        + cbor.encode("none")
        + cbor.encode("attStmt")
        + cbor.encode({})
    )

    result = _decode(attestation.hex())

    assert result["type"] == "Attestation object"
    assert [finding["code"] for finding in result["findings"]] == ["map-key-order"]
    assert result["findings"][0]["path"] == '${"fmt"}'


def test_the_codec_endpoint_returns_findings_and_the_decode_mode(client):
    response = client.post("/api/codec", json={"payload": "a201010102", "mode": "decode"})

    assert response.status_code == 200
    body = response.get_json()
    assert body["decodeMode"] == "strict"
    assert [finding["code"] for finding in body["findings"]] == ["duplicate-map-key"]


def test_canonical_input_has_no_findings():
    result = _decode(cbor.encode({1: "packed", 2: b"\x01", 3: {"alg": -7, "sig": b"\x02"}}).hex())

    assert result["findings"] == []
    assert result["malformed"] == []
