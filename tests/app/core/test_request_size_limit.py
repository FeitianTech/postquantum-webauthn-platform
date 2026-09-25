"""How large a request body the app reads (``config/request_limits.py``).

8 MiB for every route; 16 MiB for the metadata upload, which takes the whole
MDS metadata (about 7.4 MB). A body over the limit is answered 413, as JSON,
before any route reads it. The bodies are built to a byte-exact size, and to
fail quickly once read: a decoder payload that is blank but for one character,
a metadata file that is blank but for one character.
"""
from __future__ import annotations

import json

import pytest

from server.app.config import request_limits

_MIB = 1024 * 1024
_LIMIT = 8 * _MIB
_UPLOAD_LIMIT = 16 * _MIB


def _json_body(size: int) -> bytes:
    """A JSON body of exactly ``size`` bytes whose payload is one "x" after blanks."""

    empty = len(json.dumps({"payload": "x"}).encode())
    body = json.dumps({"payload": " " * (size - empty) + "x"}).encode()
    assert len(body) == size
    return body


def _upload_body(size: int) -> tuple[bytes, str]:
    """A multipart metadata upload of exactly ``size`` bytes: one file, not JSON."""

    boundary = "size-limit-boundary"
    head = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="files"; filename="metadata.json"\r\n'
        "Content-Type: application/json\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    body = head + b" " * (size - len(head) - len(tail) - 1) + b"x" + tail
    assert len(body) == size
    return body, f"multipart/form-data; boundary={boundary}"


def test_the_limits_are_the_defaults_unless_the_environment_sets_them(make_app, monkeypatch):
    app = make_app()
    assert app.config["MAX_CONTENT_LENGTH"] == _LIMIT
    assert app.config[request_limits.METADATA_UPLOAD_LIMIT_KEY] == _UPLOAD_LIMIT

    monkeypatch.setenv("FIDO_SERVER_MAX_REQUEST_BYTES", "4096")
    monkeypatch.setenv("FIDO_SERVER_MAX_METADATA_UPLOAD_BYTES", "8192")
    app = make_app()
    assert app.config["MAX_CONTENT_LENGTH"] == 4096
    assert app.config[request_limits.METADATA_UPLOAD_LIMIT_KEY] == 8192

    for invalid in ("", "0", "-5", "lots"):
        monkeypatch.setenv("FIDO_SERVER_MAX_REQUEST_BYTES", invalid)
        assert make_app().config["MAX_CONTENT_LENGTH"] == _LIMIT


@pytest.mark.parametrize("path", ["/api/decode", "/api/codec", "/api/advanced/register/complete"])
def test_a_body_at_the_limit_is_read(client, path):
    response = client.post(path, data=_json_body(_LIMIT), content_type="application/json")

    # Read, and answered by the route: the decoder cannot read "x", and the
    # registration has no ceremony to complete.
    assert response.status_code in (400, 422)
    assert "error" in response.get_json()


@pytest.mark.parametrize("path", ["/api/decode", "/api/codec", "/api/advanced/register/complete"])
def test_a_body_over_the_limit_is_refused_as_json(client, path):
    response = client.post(path, data=_json_body(_LIMIT + 1), content_type="application/json")

    assert response.status_code == 413
    assert response.get_json() == {
        "error": f"The request is larger than the limit of {_LIMIT} bytes this server accepts."
    }


def test_a_metadata_upload_over_the_general_limit_is_read(client):
    body, content_type = _upload_body(_UPLOAD_LIMIT)
    response = client.post("/api/mds/metadata/upload", data=body, content_type=content_type)

    # Read: the file is not JSON.
    assert response.status_code == 400
    (error,) = response.get_json()["errors"]
    assert error.startswith("metadata.json: Expecting value")


def test_a_metadata_upload_over_its_own_limit_is_refused_as_json(client):
    body, content_type = _upload_body(_UPLOAD_LIMIT + 1)
    response = client.post("/api/mds/metadata/upload", data=body, content_type=content_type)

    assert response.status_code == 413
    assert response.get_json() == {
        "error": f"The request is larger than the limit of {_UPLOAD_LIMIT} bytes this server accepts."
    }
