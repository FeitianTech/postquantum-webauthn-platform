"""How large a request body the app reads (``config/request_limits.py``).

8 MiB for every route; 16 MiB for the metadata upload, which takes the whole
MDS metadata (about 7.4 MB); 1 MiB for the codec, whose inputs are at most
about 60 KB. A body over the limit is answered 413, as JSON, before any route
reads it. The bodies are built to a byte-exact size, and to fail quickly once
read: a payload that is blank but for one character, a metadata file that is
blank but for one character.
"""
from __future__ import annotations

import json

import pytest

from server.app.config import request_limits

_MIB = 1024 * 1024
_LIMIT = 8 * _MIB
_UPLOAD_LIMIT = 16 * _MIB
_CODEC_LIMIT = _MIB


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
    assert app.config[request_limits.CODEC_REQUEST_LIMIT_KEY] == _CODEC_LIMIT
    assert app.config[request_limits.CODEC_ITEM_LIMIT_KEY] == 20_000

    monkeypatch.setenv("FIDO_SERVER_MAX_REQUEST_BYTES", "4096")
    monkeypatch.setenv("FIDO_SERVER_MAX_METADATA_UPLOAD_BYTES", "8192")
    monkeypatch.setenv("FIDO_SERVER_MAX_CODEC_REQUEST_BYTES", "2048")
    monkeypatch.setenv("FIDO_SERVER_MAX_CODEC_ITEMS", "500")
    app = make_app()
    assert app.config["MAX_CONTENT_LENGTH"] == 4096
    assert app.config[request_limits.METADATA_UPLOAD_LIMIT_KEY] == 8192
    assert app.config[request_limits.CODEC_REQUEST_LIMIT_KEY] == 2048
    assert app.config[request_limits.CODEC_ITEM_LIMIT_KEY] == 500

    for invalid in ("", "0", "-5", "lots"):
        monkeypatch.setenv("FIDO_SERVER_MAX_REQUEST_BYTES", invalid)
        assert make_app().config["MAX_CONTENT_LENGTH"] == _LIMIT


_ROUTE_LIMITS = [("/api/codec", _CODEC_LIMIT), ("/api/advanced/register/complete", _LIMIT)]


@pytest.mark.parametrize(("path", "limit"), _ROUTE_LIMITS)
def test_a_body_at_the_limit_is_read(client, path, limit):
    response = client.post(path, data=_json_body(limit), content_type="application/json")

    # Read, and answered by the route: the decoder cannot read "x", and the
    # registration has no ceremony to complete.
    assert response.status_code in (400, 422)
    assert "error" in response.get_json()


@pytest.mark.parametrize(("path", "limit"), _ROUTE_LIMITS)
def test_a_body_over_the_limit_is_refused_as_json(client, path, limit):
    response = client.post(path, data=_json_body(limit + 1), content_type="application/json")

    # The codec's body is far under the general limit, and refused by its own.
    assert response.status_code == 413
    assert response.get_json() == {
        "error": f"The request is larger than the limit of {limit} bytes this server accepts."
    }


def test_the_codec_refuses_a_body_over_the_limit_the_environment_sets(make_app, monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_MAX_CODEC_REQUEST_BYTES", "2048")
    client = make_app().test_client()

    assert client.post("/api/codec", data=_json_body(2048), content_type="application/json").status_code == 422
    response = client.post("/api/codec", data=_json_body(2049), content_type="application/json")
    assert response.status_code == 413
    assert response.get_json() == {"error": "The request is larger than the limit of 2048 bytes this server accepts."}


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
