"""How large a request body the app reads.

The bodies are built to a byte-exact size, and to fail quickly once read: a
decoder payload that is blank but for one character, a metadata file that is
blank but for one character.
"""
from __future__ import annotations

import io
import json

_MIB = 1024 * 1024


def _decode_body(size: int) -> bytes:
    """A /api/decode body of exactly ``size`` bytes whose payload is one "x" after blanks."""

    empty = len(json.dumps({"payload": "x"}).encode())
    body = json.dumps({"payload": " " * (size - empty) + "x"}).encode()
    assert len(body) == size
    return body


def test_a_decoder_request_of_nine_mib_is_read(client):
    response = client.post("/api/decode", data=_decode_body(9 * _MIB), content_type="application/json")

    # Read and decoded: "x" is no encoding the decoder knows.
    assert response.status_code == 422


def test_a_metadata_upload_of_seventeen_mib_is_read(client):
    upload = io.BytesIO(b" " * (17 * _MIB) + b"x")
    response = client.post(
        "/api/mds/metadata/upload",
        data={"files": (upload, "metadata.json")},
        content_type="multipart/form-data",
    )

    # Read: the file is not JSON.
    assert response.status_code == 400
    assert response.get_json()["errors"]
