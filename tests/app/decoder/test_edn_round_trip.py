"""Decode, spell as EDN, encode: the same bytes, for every item the strict parser accepts.

The required property of the EDN view: the text describes the item exactly, so
the encoder's EDN input rebuilds it byte for byte -- non-canonical heads,
indefinite lengths chunk by chunk, duplicate map keys, tags inside tags, float
widths and NaN payloads included. Checked over generated items
(``tests/app/cbor_items.py``) and over every item the repository's tests and
golden records hold (``tests/app/codec_corpus.py``).

Through the decoder and the encoder too: for every item the decoder reads as
CBOR, the ``data.edn`` it answers with, sent to the encoder's EDN input, gives
back the input -- after the CTAP command or status byte, which ``data.ctap``
holds. The decoder reads a few items as something else, by precedence: a lone
byte CTAP names, bytes that are UTF-8 JSON text, bytes shaped like
authenticator data. Those are named and counted, and nothing else may happen.
"""
from __future__ import annotations

import json

import pytest
from hypothesis import event, example, given, settings

from server.app.decoder import decode_payload_text, edn, encode_payload_text
from server.app.decoder.decode.cbor_parser import decode_item

from .. import cbor_items, codec_corpus


def _round_trip(data: bytes) -> None:
    node, end, skipped = decode_item(data)
    assert end == len(data) and not skipped
    for inline in (False, True):
        text = edn.spell(node, inline=inline)
        assert edn.encode(text) == data, text


@settings(max_examples=3000)
@given(cbor_items.items)
def test_every_generated_item_round_trips_through_its_edn(data):
    _round_trip(data)


@pytest.mark.parametrize(("name", "data"), sorted(codec_corpus.corpus().items()), ids=lambda value: str(value)[:60])
def test_every_item_in_the_repository_round_trips_through_its_edn(name, data):
    _round_trip(data)


# The readings other than CBOR, one each, so every run exercises them.
_AUTH_DATA_SHAPED = bytes([0x58, 0x23]) + bytes(30) + b"\x01" + bytes(4)  # h'<35 bytes>', flags UP


def _through_the_decoder_and_encoder(data: bytes) -> str:
    """Decode ``data``'s hex, encode the EDN the decoder shows; the reading taken."""

    result = decode_payload_text(data.hex())
    shown = result["data"]
    readings = [(finding["readAs"], finding["code"]) for finding in result["findings"] if "readAs" in finding]
    assert ("json", "ambiguous-input") not in readings, "read as the JSON number its hex spells"
    if "edn" in shown:
        prefix = bytes([shown["ctap"]["code"]]) if "ctap" in shown else b""
        encoded = encode_payload_text(shown["edn"], "EDN")["data"]["binary"]["hex"]
        assert prefix + bytes.fromhex(encoded) == data, shown["edn"]
        return "CBOR, and its EDN" + (" after a CTAP byte" if prefix else "")
    if len(data) == 1 and "ctap" in shown:
        return "a lone CTAP command or status byte"
    if result["type"] == "Authenticator data":
        return "authenticator data"
    if result["type"] == "JSON" and shown.get("json") == json.loads(data.decode("utf-8")):
        return "UTF-8 JSON text"
    raise AssertionError(f"{data.hex()} was read as {result['type']} and shows no EDN")


@settings(max_examples=1000)
@given(cbor_items.items)
@example(b"\x05")  # TIMEOUT, or the integer 5
@example(b"\x41\xab")  # h'ab', or the CREDENTIAL_MGMT_PRE command byte and junk
@example(b"\x41\x00")  # CREDENTIAL_MGMT_PRE and the integer 0, or h'00'
@example(b"\x38\x35")  # -54, or the JSON text "85"
@example(_AUTH_DATA_SHAPED)
def test_every_generated_item_the_decoder_reads_as_cbor_encodes_back_from_its_edn(data):
    event(f"decoder reading: {_through_the_decoder_and_encoder(data)}")


@pytest.mark.parametrize(("name", "data"), sorted(codec_corpus.corpus().items()), ids=lambda value: str(value)[:60])
def test_every_item_in_the_repository_encodes_back_from_the_edn_the_decoder_shows(name, data):
    reading = _through_the_decoder_and_encoder(data)

    # The corpus's one-byte items (0x00, 0x01, 0x0a, 0x17, 0x40) are lone CTAP bytes.
    assert reading.startswith("CBOR") or (len(data) == 1 and reading == "a lone CTAP command or status byte")


def test_the_codec_endpoint_encodes_edn_and_names_where_it_is_not_valid(client):
    decoded = client.post("/api/codec", json={"payload": "a2016161016162", "mode": "decode"}).get_json()
    encoded = client.post("/api/codec", json={"payload": decoded["data"]["edn"], "mode": "encode", "format": "EDN"})

    assert encoded.status_code == 200
    assert encoded.get_json()["type"] == "EDN (encoded)"
    assert encoded.get_json()["data"]["binary"]["hex"] == "a2016161016162"

    refused = client.post("/api/codec", json={"payload": "[1, 256_0]", "mode": "encode", "format": "EDN"})
    assert refused.status_code == 422
    assert refused.get_json() == {"error": "EDN is not valid at offset 4: 256 does not fit in a 1-byte argument"}
