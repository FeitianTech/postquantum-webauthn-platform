"""The decoder shows the item it read as EDN (``data.edn``), beside the decoded value.

``decodedValue`` is JSON and cannot tell ``{1: "a"}`` from ``{"1": "a"}``; the
EDN can, and it encodes back to the bytes that were decoded.
"""
from __future__ import annotations

from server.app.decoder import decode_payload_text, edn
from server.app.decoder.decode import cbor_parser, edn_view
from tests.app.decoder.real_vectors import (
    GET_ASSERTION_RESPONSE,
    MAKE_CREDENTIAL_RESPONSE,
)


def test_an_integer_key_and_a_text_key_decode_alike_and_spell_apart():
    integer_key = decode_payload_text("a1016161")["data"]
    text_key = decode_payload_text("a161316161")["data"]

    assert integer_key["decodedValue"] == text_key["decodedValue"] == {"1": "a"}
    assert integer_key["edn"] == '{1: "a"}'
    assert text_key["edn"] == '{"1": "a"}'


def test_the_edn_shows_what_the_decoded_value_cannot():
    assert decode_payload_text("a2016161016162")["data"] == {"decodedValue": {"1": "b"}, "edn": '{1: "a", 1: "b"}'}
    assert decode_payload_text("1805")["data"]["edn"] == "5_0"
    assert decode_payload_text("5f41015801 02ff".replace(" ", ""))["data"]["edn"] == "(_ h'01', h'02'_0)"
    assert decode_payload_text("f97e01")["data"] == {"decodedValue": {"diagnostic": "NaN"}, "edn": "float'7e01'"}


def test_a_ctap_message_shows_the_edn_of_the_item_after_its_status_byte():
    data = decode_payload_text(("00" + MAKE_CREDENTIAL_RESPONSE.hex()))["data"]

    assert "ctapDecoded" in data and "decodedValue" not in data
    assert data["ctap"]["code"] == 0
    assert edn.encode(data["edn"]) == MAKE_CREDENTIAL_RESPONSE


def test_a_ctap_response_without_a_status_byte_shows_its_edn():
    data = decode_payload_text(GET_ASSERTION_RESPONSE.hex())["data"]

    assert "getAssertionResponse" in data["ctapDecoded"]
    assert data["edn"].startswith("{\n  1: {")


def test_a_one_byte_byte_string_after_the_0x41_fallback_is_spelled_as_one():
    assert decode_payload_text("41ab")["data"] == {"decodedValue": "ab", "edn": "h'ab'"}


def test_a_lenient_decode_shows_edn_only_for_an_item_it_read_whole():
    assert decode_payload_text("a16161", lenient=True)["data"].get("edn") is None  # the key's value is missing
    assert decode_payload_text("820102", lenient=True)["data"]["edn"] == "[1, 2]"


def test_no_edn_is_given_that_does_not_encode_back_to_the_item():
    node, _end, _ = cbor_parser.decode_item(bytes.fromhex("820102"))

    assert edn_view.extra(node, bytes.fromhex("820102")) == {"edn": "[1, 2]"}
    assert edn_view.extra(node, bytes.fromhex("820103")) == {}  # the text is right, the bytes are not the item
    assert edn_view.extra({"majorType": 0, "value": 1}, b"\x01") == {}  # no offsets: nothing to compare with


def test_the_endpoint_answers_with_the_edn(client):
    response = client.post("/api/decode", json={"payload": "a1016161"})

    assert response.status_code == 200
    assert response.get_json()["data"]["edn"] == '{1: "a"}'
