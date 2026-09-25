"""The CTAP/WebAuthn format given the decoder's own view of a CTAP message.

The format reads a map numbered by CTAP members. Given a decoder answer, it
took the first numbered map it found in it and guessed which message it was
from its values' lengths.
"""
from __future__ import annotations

import json

import pytest

from server.app.decoder import decode_payload_text, encode_payload_text
from server.app.decoder.cbor_canonical import _canonical_cbor_dumps
from tests.app.decoder.real_vectors import GET_ASSERTION_RESPONSE

_FORMAT = "CBOR (CTAP/WebAuthn Data)"
_AUTH_DATA = bytes(32) + b"\x01" + bytes(4)


def _encode(message: bytes) -> bytes:
    decoded = decode_payload_text(message.hex())["data"]
    return bytes.fromhex(encode_payload_text(json.dumps(decoded), _FORMAT)["data"]["binary"]["hex"])


def test_a_make_credential_response_with_fmt_none_is_taken_for_a_request():
    # "none" is base64 of three bytes; the format took it for a clientDataHash.
    message = b"\x00" + _canonical_cbor_dumps({1: "none", 2: _AUTH_DATA, 3: {}})

    with pytest.raises(ValueError, match=r"Field 0x01 \(clientDataHash\) must be exactly 32 bytes for MakeCredential request"):
        _encode(message)


def test_a_response_decoded_without_its_status_byte_comes_back_with_one():
    assert _encode(GET_ASSERTION_RESPONSE) == b"\x00" + GET_ASSERTION_RESPONSE
