"""The encoder refuses JSON input that repeats a key, rather than encode one of its values.

``json.loads`` keeps the later value and drops the earlier without a word, so
``{"a": 1, "a": 2}`` used to encode as ``{"a": 2}``. EDN input can repeat a key.
"""
from __future__ import annotations

import pytest

from server.app.decoder.encode import encode_payload_text


@pytest.mark.parametrize("target", ["cbor", "json", "cose", "CBOR (CTAP/WebAuthn Data)"])
def test_json_input_that_repeats_a_key_is_refused_naming_it(target):
    with pytest.raises(ValueError, match=r'The JSON repeats the key "a" at \$\{"x"\}\{"a"\}'):
        encode_payload_text('{"x": {"a": 1, "a": 2}}', target)


def test_the_same_map_is_encoded_from_edn():
    assert encode_payload_text('{"a": 1, "a": 2}', "EDN")["data"]["binary"]["hex"] == "a2616101616102"


def test_json_without_a_repeated_key_still_encodes():
    assert encode_payload_text("null", "cbor")["data"]["binary"]["hex"] == "f6"
    assert encode_payload_text('{"a": {"a": 1}}', "cbor")["data"]["binary"]["hex"] == "a16161a1616101"


def test_the_endpoint_answers_422_naming_the_key(client):
    response = client.post("/api/codec", json={"payload": '{"a": 1, "a": 2}', "mode": "encode", "format": "CBOR (canonical)"})

    assert response.status_code == 422
    assert response.get_json()["error"].startswith('The JSON repeats the key "a" at ${"a"}')
