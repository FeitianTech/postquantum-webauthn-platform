"""``decoder.encode.handlers_cbor``: format CBOR writes a CTAP message only from the decoder's explicit CTAP view.

That view is ``ctapDecoded``, or ``expandedJson`` beside the ``ctap`` framing that names
its message; any other object is a plain map, whatever its keys look like.
"""
from __future__ import annotations

import json

from server.app.decoder.encode import text as encode_text

MAKE_CREDENTIAL = {
    # A view's members by number, its values in the view's spelling: bytes as hex.
    "1 (clientDataHash)": "11" * 32,
    "2 (rp)": {"id": "example.com", "name": "Example"},
    "3 (user)": {"id": b"user".hex(), "name": "alice", "displayName": "Alice"},
    "4 (pubKeyCredParams)": [{"alg": -7, "type": "public-key"}],
}
GET_ASSERTION = {"1 (rpId)": "example.com", "2 (clientDataHash)": "22" * 32}


def _cbor(value):
    return encode_text.encode_payload_text(json.dumps(value), "CBOR")


def test_a_ctap_decoded_view_is_written_as_its_message_after_its_byte():
    answer = _cbor({"ctap": {"code": 1, "codeHex": "0x01", "kind": "command"}, "ctapDecoded": {"makeCredentialRequest": MAKE_CREDENTIAL}})

    assert answer["type"] == "CBOR (canonical) (encoded makeCredentialRequest)"
    assert answer["data"]["ctap"]["code"] == 1
    assert answer["data"]["binary"]["hex"].startswith("01a4")


def test_expanded_json_is_a_ctap_view_only_beside_the_framing_that_names_it():
    framing = {"code": 2, "codeHex": "0x02", "kind": "command", "message": "getAssertionRequest"}

    framed = _cbor({"expandedJson": GET_ASSERTION, "ctap": framing})
    plain = _cbor({"expandedJson": {"rpId": "example.com"}})

    assert framed["type"] == "CBOR (canonical) (encoded getAssertionRequest)"
    assert plain["type"] == "CBOR (canonical) (encoded)"
    assert "ctap" not in plain["data"]


def test_a_map_with_ctap_member_names_is_still_a_plain_map():
    # A root map with CTAP member names was once read as a makeCredential response.
    answer = _cbor({"fmt": "none", "authData": "00" * 37})

    assert answer["type"] == "CBOR (canonical) (encoded)"
    assert "ctapDecoded" not in answer["data"]
    assert answer["data"]["binary"]["hex"].startswith("a263666d74646e6f6e65")


def test_anything_else_is_written_as_plain_cbor():
    answer = _cbor([1, 2, 3])

    assert answer["type"] == "CBOR (canonical) (encoded)"
    assert answer["data"]["binary"]["hex"] == "83010203"
