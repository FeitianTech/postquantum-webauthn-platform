"""``decoder.encode.binary_decode``: a JSON value read as bytes for the encoder, and an x5c certificate's bytes."""
from __future__ import annotations

import json

import pytest

from server.app.decoder.encode import text as encode_text
from tests.app.security.ceremony_helpers import b64u

CTAP = "CBOR (CTAP/WebAuthn Data)"
# Bytes whose base64url is no hex, so it is read as base64url.
AUTH_DATA = b64u(b"\xab" * 37)


def _pem_bytes(value) -> str:
    return encode_text.encode_payload_text(json.dumps(value), "PEM")["data"]["binary"]["hex"]


@pytest.mark.parametrize(
    ("value", "hex_bytes"),
    [("   ", ""), ({"bytes": [1, 2]}, "0102"), ({"hex": "zz", "base64": "AQI="}, "0102"), ({"base64url": "AQI"}, "0102")],
)
def test_a_value_is_read_as_hex_base64_base64url_or_byte_values(value, hex_bytes):
    assert _pem_bytes(value) == hex_bytes


@pytest.mark.parametrize(
    "value",
    [
        {"hex": "zz"},
        {"base64": "A"},
        {"base64url": "A"},
        {"pem": "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"},
        [1, 2, 300],
    ],
)
def test_a_value_in_no_alphabet_is_no_bytes(value):
    with pytest.raises(ValueError, match="Unable to extract binary payload"):
        _pem_bytes(value)


def _make_credential_response(x5c) -> dict:
    return {"1": "packed", "2": AUTH_DATA, "3": {"alg": -7, "sig": b64u(b"s"), "x5c": x5c}}


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        ({"pem": "-----BEGIN CERTIFICATE-----\n====\n-----END CERTIFICATE-----"}, "Unable to decode certificate PEM contents"),
        ({"pem": "===="}, "Unable to decode certificate PEM contents"),
        ({"pem": 123}, r"Unable to recover certificate bytes for x5c\[0\]"),
        (5, r"Unable to recover certificate bytes for x5c\[0\]"),
    ],
)
def test_an_x5c_certificate_that_holds_no_bytes_is_refused(entry, error):
    with pytest.raises(ValueError, match=error):
        encode_text.encode_payload_text(json.dumps(_make_credential_response([entry])), CTAP)
