"""Decoded JSON re-encodes exactly, or is refused: nothing is dropped on the way.

The encoder's four CTAP builders used to read only the members their table
names, so anything else -- an unknown member, a second message, the bytes the
decoder found after authData -- vanished from the output without a word. Now an
unknown member is refused (from JSON alone, a hex string could have been a byte
string or text, so passing it through would be a guess), and authData's trailing
bytes are put back.
"""
from __future__ import annotations

import json

import cbor2
import pytest

from server.app.decoder import decode_payload_text, encode_payload_text
from tests.app.decoder.real_vectors import (
    GET_ASSERTION_RESPONSE,
    MAKE_CREDENTIAL_RESPONSE,
)

_AUTH_DATA = bytes(32) + b"\x01" + (9).to_bytes(4, "big")


def _decoded(data: bytes) -> dict:
    return decode_payload_text(data.hex())["data"]


def _encode(body: dict) -> bytes:
    result = encode_payload_text(json.dumps(body), "cbor")
    return bytes.fromhex(result["data"]["binary"]["hex"])


@pytest.mark.parametrize(
    ("message", "kind"),
    [
        (b"\x00" + cbor2.dumps({1: "none", 2: _AUTH_DATA, 3: {}, 9: b"\xab"}), "makeCredentialResponse"),
        (b"\x00" + cbor2.dumps({2: _AUTH_DATA, 3: b"\x30\x00", 9: b"\xab"}), "getAssertionResponse"),
        (b"\x02" + cbor2.dumps({1: "example.com", 2: bytes(32), 12: b"\xab"}), "getAssertionRequest"),
    ],
)
def test_a_member_ctap_does_not_define_is_refused_not_dropped(message, kind):
    decoded = _decoded(message)
    assert kind in decoded["ctapDecoded"]

    with pytest.raises(ValueError, match=f"{kind} has no member '(9|12)' in CTAP 2.2"):
        _encode(decoded)


def test_bytes_after_authdata_are_encoded_back():
    message = b"\x00" + cbor2.dumps({2: _AUTH_DATA + b"\xde\xad", 3: b"\x30\x00"})

    assert _encode(_decoded(message)) == message


def test_two_messages_in_ctap_decoded_are_refused():
    first = _decoded(b"\x00" + MAKE_CREDENTIAL_RESPONSE)["ctapDecoded"]
    second = _decoded(b"\x00" + GET_ASSERTION_RESPONSE)["ctapDecoded"]

    with pytest.raises(ValueError, match="ctapDecoded holds 2 messages"):
        _encode({"ctapDecoded": {**first, **second}})


def test_a_message_the_encoder_does_not_build_is_refused():
    with pytest.raises(ValueError, match="ctapDecoded.getInfoResponse is not a CTAP message the encoder builds"):
        _encode({"ctapDecoded": {"getInfoResponse": {"1 (versions)": ["FIDO_2_0"]}}})


def test_two_keys_for_one_member_are_refused():
    structure = {"1": "none", "1 (fmt)": "packed", "2 (authData)": _AUTH_DATA.hex(), "3 (attStmt)": {}}

    with pytest.raises(ValueError, match=r"member 1 \(fmt\) is given twice"):
        _encode({"ctapDecoded": {"makeCredentialResponse": structure}})


@pytest.mark.parametrize(
    "response", [MAKE_CREDENTIAL_RESPONSE, GET_ASSERTION_RESPONSE], ids=["makeCredential", "getAssertion"]
)
def test_real_device_responses_still_encode_back_to_the_same_bytes(response):
    message = b"\x00" + response

    assert _encode(_decoded(message)) == message
