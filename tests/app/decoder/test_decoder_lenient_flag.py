"""Best-effort decoding happens only when a request asks for it.

``"lenient": true`` on ``/api/codec`` (decode mode) or ``/api/decode`` reads CBOR
that is not well-formed as far as it goes. The response says it was lenient and
lists, with offset and path, each item it kept partially or stepped over.
"""
from __future__ import annotations

import pytest

from tests.app.decoder.test_decoder_no_repair import ES256_GET_ASSERTION_DUMP


@pytest.mark.parametrize("endpoint", ["/api/codec", "/api/decode"])
def test_without_the_flag_input_that_is_not_well_formed_fails(client, endpoint):
    response = client.post(endpoint, json={"payload": "48aabb", "mode": "decode"})

    assert response.status_code == 422
    assert response.get_json()["offset"] == 0


@pytest.mark.parametrize("endpoint", ["/api/codec", "/api/decode"])
def test_with_the_flag_the_response_says_it_was_lenient_and_what_it_skipped(client, endpoint):
    response = client.post(endpoint, json={"payload": "48aabb", "mode": "decode", "lenient": True})

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
    for endpoint in ("/api/codec", "/api/decode"):
        response = client.post(endpoint, json={"payload": "a10102", "lenient": value})

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
