"""``config.compression``: which responses are gzipped for a client that accepts gzip.

A successful response with a text-like body of at least ``RESPONSE_COMPRESSION_MIN_SIZE``
bytes is compressed when that makes it smaller; anything else is sent as it is.
"""
from __future__ import annotations

import gzip
import random

import pytest
from flask import Flask, Response

from server.app.config import compression

TEXT = b"A" * 1024
# Bytes gzip cannot shrink: the compressed form would be the larger one.
NOISE = random.Random(0).randbytes(1024)
GZIP = {"Accept-Encoding": "gzip"}


@pytest.fixture
def compressing_client():
    app = Flask(__name__)
    app.config["RESPONSE_COMPRESSION_MIN_SIZE"] = 64
    compression.init_app(app)

    @app.route("/text")
    def text():
        response = Response(TEXT, mimetype="text/plain")
        response.headers["ETag"] = '"etag"'
        response.headers["Content-MD5"] = "digest"
        return response

    @app.route("/weak")
    def weak():
        response = Response(TEXT, mimetype="text/plain")
        response.set_etag("etag", weak=True)
        return response

    @app.route("/passthrough")
    def passthrough():
        return Response(TEXT, mimetype="text/plain", direct_passthrough=True)

    @app.route("/vary")
    def vary():
        return Response(TEXT, mimetype="text/plain", headers={"Vary": "accept-encoding, Origin"})

    @app.route("/noise")
    def noise():
        return Response(NOISE, mimetype="text/plain")

    @app.route("/small")
    def small():
        return Response(b"tiny", mimetype="text/plain")

    @app.route("/binary")
    def binary():
        return Response(TEXT, mimetype="application/octet-stream")

    @app.route("/encoded")
    def encoded():
        return Response(TEXT, mimetype="text/plain", headers={"Content-Encoding": "br"})

    @app.route("/error")
    def error():
        return Response(TEXT, status=500, mimetype="text/plain")

    return app.test_client()


def test_a_text_body_is_gzipped_for_a_client_that_accepts_gzip(compressing_client):
    response = compressing_client.get("/text", headers=GZIP)

    assert response.headers["Content-Encoding"] == "gzip"
    assert response.headers["Vary"] == "Accept-Encoding"
    assert int(response.headers["Content-Length"]) == len(response.data)
    assert gzip.decompress(response.data) == TEXT
    # Both describe the uncompressed body.
    assert "ETag" not in response.headers
    assert "Content-MD5" not in response.headers


def test_a_passthrough_body_is_read_and_gzipped(compressing_client):
    response = compressing_client.get("/passthrough", headers=GZIP)

    assert gzip.decompress(response.data) == TEXT


def test_vary_keeps_its_tokens_and_names_accept_encoding_once(compressing_client):
    response = compressing_client.get("/vary", headers=GZIP)

    assert response.headers["Vary"] == "accept-encoding, Origin"


def test_nothing_is_gzipped_for_a_client_that_does_not_accept_gzip(compressing_client):
    response = compressing_client.get("/text")

    assert "Content-Encoding" not in response.headers
    assert response.data == TEXT


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/noise", NOISE),  # gzip would make it larger
        ("/small", b"tiny"),  # under RESPONSE_COMPRESSION_MIN_SIZE
        ("/binary", TEXT),  # not a text-like type
        ("/error", TEXT),  # not a success
    ],
)
def test_a_body_that_does_not_qualify_is_sent_uncompressed(compressing_client, path, body):
    response = compressing_client.get(path, headers=GZIP)

    assert "Content-Encoding" not in response.headers
    assert response.data == body


def test_a_body_that_is_already_encoded_is_left_alone(compressing_client):
    response = compressing_client.get("/encoded", headers=GZIP)

    assert response.headers["Content-Encoding"] == "br"
    assert response.data == TEXT


def test_outside_a_request_nothing_is_gzipped():
    response = Response(TEXT, mimetype="text/plain")

    assert compression.maybe_compress_response(response) is response
    assert response.data == TEXT


def test_a_weak_validator_survives_gzip_because_it_names_equivalent_content(compressing_client):
    response = compressing_client.get("/weak", headers=GZIP)

    assert gzip.decompress(response.data) == TEXT
    assert response.get_etag() == ("etag", True)
