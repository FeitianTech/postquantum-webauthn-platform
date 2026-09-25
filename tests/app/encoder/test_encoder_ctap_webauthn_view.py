"""The CTAP/WebAuthn format given the decoder's own view of a CTAP message.

The format reads a map numbered by CTAP members. Given a decoder answer, it
took the first numbered map it found in it and guessed which message it was
from its values' lengths; now a view, beside its framing, is rebuilt as format
CBOR rebuilds it (``encode/ctap_views.py``), exactly.
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


@pytest.mark.parametrize(
    "message",
    [
        # "none" is base64 of three bytes; the format took it for a clientDataHash.
        b"\x00" + _canonical_cbor_dumps({1: "none", 2: _AUTH_DATA, 3: {}}),
        # A response decoded without its status byte came back with one.
        GET_ASSERTION_RESPONSE,
        b"\x00" + GET_ASSERTION_RESPONSE,
    ],
    ids=["fmt none", "no status byte", "status byte"],
)
def test_a_decoder_view_is_rebuilt_as_it_is(message):
    assert _encode(message) == message


def test_a_hand_written_numbered_map_is_still_read_as_the_format_reads_one():
    body = {"01": "example.com", "02": "22" * 32}

    encoded = encode_payload_text(json.dumps(body), _FORMAT)

    assert encoded["type"] == "CBOR (CTAP/WebAuthn Data) (encoded getAssertionRequest)"
    assert encoded["data"]["binary"]["hex"].startswith("02a2")
