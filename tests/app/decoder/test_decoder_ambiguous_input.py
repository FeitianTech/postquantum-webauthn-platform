"""Input that is valid hexadecimal and a valid JSON number is never read silently.

The precedence (``decode/ambiguous_input.py``): hexadecimal when the bytes are
one well-formed CBOR item, after at most one CTAP command or status byte, with
nothing after it; otherwise the JSON number. Either way an ``ambiguous-input``
finding names the reading that was not taken.
"""
from __future__ import annotations

import json

import pytest

from server.app.decoder import decode_payload_text
from server.app.decoder.decode import ambiguous_input


def _ambiguity(result: dict) -> list[tuple[str, str]]:
    """The finding about the text's hexadecimal and JSON-number readings; the bytes' readings are other tests'."""

    return [
        (finding["readAs"], finding["alsoValidAs"])
        for finding in result["findings"]
        if finding["code"] == "ambiguous-input" and {finding["readAs"], finding["alsoValidAs"]} == {"hex", "json"}
    ]


@pytest.mark.parametrize(
    ("text", "decoded"),
    [
        ("81818101", [[[1]]]),
        ("8101", [1]),
        ("10", 16),
        ("1901f4", None),  # not digits only: never JSON, so never ambiguous
        # A one-byte byte string: 0x41 is also a command byte, and what follows it
        # alone is no item. These used to be read as JSON numbers, "not one item".
        ("4118", "18"),
        ("4161", "61"),
        ("4142", "42"),
    ],
)
def test_digits_that_are_one_cbor_item_are_read_as_hex(text, decoded):
    result = decode_payload_text(text)

    assert result["type"] == "CBOR"
    if decoded is None:
        assert _ambiguity(result) == []
    else:
        assert result["data"]["decodedValue"] == decoded
        assert _ambiguity(result) == [("hex", "json")]


@pytest.mark.parametrize(
    ("text", "number"),
    [
        ("818181", 818181),  # the innermost array has no item
        ("99", 99),  # 0x99 needs two more bytes
        ("1234", 1234),  # 0x12 is one item; 0x34 is left over
        ("12e4", 120000.0),  # an exponent is hex digits too
    ],
)
def test_digits_that_are_not_one_cbor_item_are_read_as_json_and_say_so(text, number):
    result = decode_payload_text(text)

    assert result["type"] == "JSON"
    assert result["data"]["json"] == number
    assert _ambiguity(result) == [("json", "hex")]


def test_a_lone_ctap_status_byte_is_hex_and_names_the_json_number():
    result = decode_payload_text("31")

    assert result["type"] == "CBOR (PIN_INVALID status)"
    assert _ambiguity(result) == [("hex", "json")]


def test_the_findings_say_which_reading_was_taken_and_why():
    (hex_finding,) = decode_payload_text("8101")["findings"]
    (json_finding,) = decode_payload_text("99")["findings"]

    assert hex_finding["message"] == (
        "the input is also the JSON number 8101; it was read as hexadecimal, because "
        "those bytes are one well-formed CBOR item (after any CTAP command or status byte)"
    )
    assert json_finding["message"] == (
        "the input is also hexadecimal (h'99'); it was read as the JSON number 99, "
        "because those bytes are not one well-formed CBOR item"
    )
    assert (hex_finding["category"], hex_finding["offset"], hex_finding["path"]) == ("input", 0, "$")


@pytest.mark.parametrize("text", ["1e5", "-42", "3.25", "04", "true", '"12"', "0x10"])
def test_text_that_reads_only_one_way_carries_no_ambiguity(text):
    assert _ambiguity(decode_payload_text(text)) == []


def test_lenient_decoding_does_not_change_which_reading_wins():
    result = decode_payload_text("99", lenient=True)

    assert result["type"] == "JSON"
    assert _ambiguity(result) == [("json", "hex")]


def test_the_endpoint_reads_digit_hex_as_cbor(client):
    response = client.post("/api/decode", json={"payload": "81818101"})

    assert response.status_code == 200
    assert response.get_json()["data"]["decodedValue"] == [[[1]]]


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\x31", True),  # a status byte on its own
        (b"\x01\xa0", True),  # a command byte and an empty map
        (b"\x81\x01", True),
        (b"\x12\x34", False),  # one item, then a byte
        (b"\x99", False),  # truncated
        (b"\x00", True),  # SUCCESS
        (b"\x41\x18", True),  # h'18': 0x41 then 0x18 alone is no item, but the two are one
        (b"\x41\xa1\x01", False),  # neither reading is well-formed
    ],
)
def test_is_one_ctap_message(data, expected):
    assert ambiguous_input.is_one_ctap_message(data) is expected


# encoding.sniff() flags text that base64 and base64url both read, to the same
# bytes. A binary field's "encoding" says so instead of asserting "base64".


@pytest.mark.parametrize(
    ("raw_id", "encoding"),
    [
        ("BwcHBwcHBwcHBwcHBwcHBw", "base64 or base64url"),  # letters and digits only
        ("-wcHBwcHBwcHBwcHBwcHBw", "base64url"),
        ("+wcHBwcHBwcHBwcHBwcHBw", "base64"),
    ],
)
def test_a_binary_field_names_every_alphabet_that_reads_it(raw_id, encoding):
    credential = {"id": raw_id, "rawId": raw_id, "type": "public-key", "response": {"signature": "MEQCIA"}}

    result = decode_payload_text(json.dumps(credential))

    assert result["data"]["credential"]["rawId"]["binary"]["encoding"] == encoding
