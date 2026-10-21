"""JSON is read at most 64 deep, as CBOR and EDN are (``decode/json_input.py``).

RFC 8259 section 9 lets a parser limit how deep it reads. Deeper JSON is
refused, 422, with the offset and path of the first value too deep, decoded or
encoded, strict or lenient; inside a credential's field it is that field's
error. Before, JSON deeper than Python's stack answered 500.
"""
from __future__ import annotations

import base64
import json

import pytest

_PATH = "$" + "[0]" * 65
_REFUSED = f"JSON nested too deep at offset 65 ({_PATH}): values are nested more than 64 deep, the most the decoder reads"


@pytest.mark.parametrize("lenient", [False, True])
@pytest.mark.parametrize("payload", ["[" * 65 + "1" + "]" * 65, "[" * 100_000 + "]" * 100_000], ids=["65", "100000"])
def test_decoding_json_nested_too_deep_is_refused_where_it_goes_too_deep(client, payload, lenient):
    response = client.post("/api/codec", json={"payload": payload, "lenient": lenient})

    assert response.status_code == 422
    assert response.get_json() == {"error": _REFUSED, "offset": 65, "path": _PATH}


def test_decoding_json_nested_64_deep_reads_it(client):
    payload = "[" * 64 + "1" + "]" * 64

    response = client.post("/api/codec", json={"payload": payload})

    assert response.status_code == 200
    assert response.get_json()["data"]["json"] == json.loads(payload)


@pytest.mark.parametrize("target", ["CBOR", "JSON"])
def test_encoding_json_nested_too_deep_is_refused(client, target):
    response = client.post(
        "/api/codec", json={"payload": "[" * 65 + "1" + "]" * 65, "mode": "encode", "format": target}
    )

    assert response.status_code == 422
    assert response.get_json() == {"error": _REFUSED, "offset": 65, "path": _PATH}


def test_client_data_nested_too_deep_in_a_credential_is_that_fields_error(client):
    client_data = b'{"type": "webauthn.get", "challenge": "AAAA", "origin": "https://x", "n": ' + b"[" * 64 + b"1" + b"]" * 64 + b"}"
    credential = {
        "id": "AAAA",
        "type": "public-key",
        "response": {"clientDataJSON": base64.urlsafe_b64encode(client_data).decode().rstrip("=")},
    }

    response = client.post("/api/codec", json={"payload": json.dumps(credential)})

    assert response.status_code == 200
    (finding,) = response.get_json()["findings"]
    assert (finding["code"], finding["offset"], finding["path"], finding["source"]) == (
        "parse-error", client_data.index(b"[") + 64, '${"n"}' + "[0]" * 64, "response.clientDataJSON"
    )
