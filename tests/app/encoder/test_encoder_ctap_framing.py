"""A CTAP message's framing: the command or status byte before it, the bytes after it.

The decoder's view is encoded back to a message; what the input held around the
map -- a byte before it or none, bytes after it -- is the framing ``data.ctap``
holds beside the view.
"""
from __future__ import annotations

import json

import pytest

from server.app.decoder import decode_payload_text, encode_payload_text
from tests.app.decoder.real_vectors import (
    GET_ASSERTION_RESPONSE,
    MAKE_CREDENTIAL_RESPONSE,
)


def _round_trip(message: bytes, **replace) -> tuple[dict, bytes]:
    decoded = decode_payload_text(message.hex())["data"]
    body = {**decoded, **replace}
    encoded = encode_payload_text(json.dumps(body), "CBOR")
    return decoded, bytes.fromhex(encoded["data"]["binary"]["hex"])


def test_a_response_sent_without_its_status_byte_comes_back_without_one():
    decoded, encoded = _round_trip(GET_ASSERTION_RESPONSE)

    assert decoded["ctap"] == {"code": None, "message": "getAssertionResponse", "payloadLength": len(GET_ASSERTION_RESPONSE)}
    assert encoded == GET_ASSERTION_RESPONSE


def test_the_bytes_after_a_message_come_back():
    decoded, encoded = _round_trip(b"\x00" + MAKE_CREDENTIAL_RESPONSE + b"\xab\xcd")

    assert decoded["ctap"]["trailingBytesHex"] == "abcd"
    assert encoded == b"\x00" + MAKE_CREDENTIAL_RESPONSE + b"\xab\xcd"


def test_padding_after_a_message_is_counted_and_comes_back():
    decoded, encoded = _round_trip(b"\x00" + MAKE_CREDENTIAL_RESPONSE + b"\x00\xff")

    assert decoded["ctap"]["paddingBytes"] == 2
    assert decoded["ctap"]["trailingBytesHex"] == "00ff"
    assert encoded == b"\x00" + MAKE_CREDENTIAL_RESPONSE + b"\x00\xff"


def test_a_ctap_view_without_its_framing_is_refused():
    decoded = decode_payload_text((b"\x00" + MAKE_CREDENTIAL_RESPONSE).hex())["data"]

    with pytest.raises(ValueError, match="ctapDecoded is encoded with the ctap object the decoder gives beside it"):
        encode_payload_text(json.dumps({"ctapDecoded": decoded["ctapDecoded"]}), "CBOR")


@pytest.mark.parametrize(
    ("framing", "message"),
    [
        ({"codeHex": "0x00"}, "ctap.code is missing"),
        ({"code": "0x00"}, 'ctap.code must be a byte \\(0 to 255\\), or null for none; it is "0x00"'),
        ({"code": 256}, "ctap.code must be a byte"),
        ({"code": True}, "ctap.code must be a byte"),
        ({"code": 0, "trailingBytesHex": "zz"}, "ctap.trailingBytesHex must be hex"),
        ({"code": 0, "message": "getAssertionResponse"}, "ctapDecoded shows a makeCredentialResponse, but ctap.message says it is a getAssertionResponse"),
    ],
)
def test_framing_the_encoder_cannot_write_is_refused(framing, message):
    decoded = decode_payload_text((b"\x00" + MAKE_CREDENTIAL_RESPONSE).hex())["data"]

    with pytest.raises(ValueError, match=message):
        encode_payload_text(json.dumps({"ctapDecoded": decoded["ctapDecoded"], "ctap": framing}), "CBOR")
