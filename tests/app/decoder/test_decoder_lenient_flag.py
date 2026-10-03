"""Best-effort decoding happens only when a request asks for it.

``"lenient": true`` on ``/api/codec`` (decode mode) reads CBOR
that is not well-formed as far as it goes. The response says it was lenient and
lists, with offset and path, each item it kept partially or stepped over.
"""
from __future__ import annotations

import pytest

from tests.app.decoder.test_decoder_no_repair import ES256_GET_ASSERTION_DUMP


def test_without_the_flag_input_that_is_not_well_formed_fails(client):
    response = client.post("/api/codec", json={"payload": "48aabb", "mode": "decode"})

    assert response.status_code == 422
    assert response.get_json()["offset"] == 0


def test_with_the_flag_the_response_says_it_was_lenient_and_what_it_skipped(client):
    response = client.post("/api/codec", json={"payload": "48aabb", "mode": "decode", "lenient": True})

    assert response.status_code == 200
    body = response.get_json()
    assert body["decodeMode"] == "lenient"
    assert body["data"]["decodedValue"] == "aabb"
    assert body["findings"] == [
        {
            "code": "truncated",
            "category": "skipped",
            "offset": 0,
            "path": "$",
            "message": "byte string declares 8 bytes; 2 remain",
        }
    ]
    assert body["malformed"] == ["byte string declares 8 bytes; 2 remain"]


@pytest.mark.parametrize("value", ["true", 1, None, "yes"])
def test_the_flag_must_be_a_boolean(client, value):
    response = client.post("/api/codec", json={"payload": "a10102", "lenient": value})

    assert response.status_code == 400
    assert response.get_json() == {"error": "lenient must be true or false."}


def test_strict_is_the_default_and_well_formed_input_skips_nothing_either_way(client):
    strict = client.post("/api/codec", json={"payload": "a10102"}).get_json()
    lenient = client.post("/api/codec", json={"payload": "a10102", "lenient": True}).get_json()

    assert strict["decodeMode"] == "strict"
    assert lenient["decodeMode"] == "lenient"
    assert strict["data"] == lenient["data"]
    assert strict["findings"] == lenient["findings"] == []


def test_a_lenient_decode_of_the_corrupt_get_assertion_dump_shows_what_is_there_and_nothing_more(client):
    response = client.post(
        "/api/codec", json={"payload": ES256_GET_ASSERTION_DUMP, "mode": "decode", "lenient": True}
    )

    body = response.get_json()
    assert response.status_code == 200
    assert body["type"] == "CBOR (SUCCESS status)"
    skipped = [finding for finding in body["findings"] if finding["category"] == "skipped"]
    assert [(finding["code"], finding["message"]) for finding in skipped] == [
        ("missing-map-value", "map key 1 has no value"),
        ("truncated", "map declares 5 entries; the data ends after 3"),
    ]
    # What was read is shown as read: the signature bytes as a map key, no
    # signature member, and no getAssertion response labels.
    decoded = body["data"]["decodedValue"]
    assert sorted(decoded) == sorted(["1", "2", _signature_key(decoded)])
    assert "ctapDecoded" not in body["data"]


def _signature_key(decoded: dict) -> str:
    (key,) = [key for key in decoded if key.startswith("3045022100aad84e")]
    return key


def test_a_ctap_response_with_an_integer_key_it_could_not_read_is_shown(client):
    # makeCredential's response with a fourth key whose head (0x1f) no integer has.
    auth_data = (bytes(32) + b"\x01" + (7).to_bytes(4, "big")).hex()
    payload = "00a401667061636b6564025825" + auth_data + "03a0" + "1f01"

    response = client.post("/api/codec", json={"payload": payload, "mode": "decode", "lenient": True})

    assert response.status_code == 200
    shown = response.get_json()["data"]["ctapDecoded"]["makeCredentialResponse"]
    assert shown["invalid(invalid(h'1f') at offset 52) (invalid)"] == 1
    assert shown["1 (fmt)"] == "packed"


def test_a_ctap_member_whose_key_or_value_holds_an_unreadable_item_is_shown(client):
    # A tag (0xcc: 12) around a head no item has (0x1e), as a fourth key and as member 7.
    auth_data = (bytes(32) + b"\x01" + (7).to_bytes(4, "big")).hex()
    payload = "00a501667061636b6564025825" + auth_data + "03a0" + "cc1e01" + "07cc1e"

    response = client.post("/api/codec", json={"payload": payload, "mode": "decode", "lenient": True})

    assert response.status_code == 200
    shown = response.get_json()["data"]["ctapDecoded"]["makeCredentialResponse"]
    assert shown["invalid(tag(12) at offset 52) (invalid)"] == 1
    assert shown["7"] == "invalid(tag(12) at offset 56) (invalid)"
