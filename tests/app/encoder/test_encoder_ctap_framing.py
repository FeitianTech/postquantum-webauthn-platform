"""A CTAP message's framing: the command or status byte before it, the bytes after it.

The decoder's view is encoded back to a message; what the input held around the
map -- a byte before it or none, bytes after it -- is the framing ``data.ctap``
holds beside the view.
"""
from __future__ import annotations

import json

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


def test_a_response_sent_without_its_status_byte_comes_back_with_one():
    decoded, encoded = _round_trip(GET_ASSERTION_RESPONSE)

    assert "ctap" not in decoded
    assert encoded == b"\x00" + GET_ASSERTION_RESPONSE


def test_the_bytes_after_a_message_are_shown_and_dropped():
    decoded, encoded = _round_trip(b"\x00" + MAKE_CREDENTIAL_RESPONSE + b"\xab\xcd")

    assert decoded["ctap"]["trailingBytesHex"] == "abcd"
    assert encoded == b"\x00" + MAKE_CREDENTIAL_RESPONSE


def test_padding_after_a_message_is_counted_and_dropped():
    decoded, encoded = _round_trip(b"\x00" + MAKE_CREDENTIAL_RESPONSE + b"\x00\xff")

    assert decoded["ctap"]["ignoredPaddingBytes"] == 2
    assert "trailingBytesHex" not in decoded["ctap"]
    assert encoded == b"\x00" + MAKE_CREDENTIAL_RESPONSE


def test_a_ctap_view_without_its_framing_is_given_a_byte():
    decoded = decode_payload_text((b"\x00" + MAKE_CREDENTIAL_RESPONSE).hex())["data"]

    encoded = encode_payload_text(json.dumps({"ctapDecoded": decoded["ctapDecoded"]}), "CBOR")

    assert encoded["data"]["binary"]["hex"] == (b"\x00" + MAKE_CREDENTIAL_RESPONSE).hex()
