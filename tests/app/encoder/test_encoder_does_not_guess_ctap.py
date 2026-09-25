"""Format ``cbor`` never reads a plain map as a CTAP message.

A root map whose keys looked like CTAP members -- "1", "3", "credential",
"signature" -- was read as a getAssertion response: ``{"1": "a"}`` failed with
"credential descriptor must be an object for encoding", and ``{"2": "aa", "3":
"bb"}`` came back as a CTAP response with a 0x00 status byte in front. CTAP is
encoded only from the decoder's explicit view (``ctapDecoded``, or
``expandedJson`` beside its ``ctap`` metadata) or with the ``ctap-webauthn``
format; everything else is JSON, encoded as it reads.
"""
from __future__ import annotations

import json

import pytest

from server.app.decoder import decode_payload_text
from server.app.decoder.encode import encode_payload_text
from tests.app.decoder.real_vectors import (
    GET_ASSERTION_RESPONSE,
    MAKE_CREDENTIAL_RESPONSE,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"1": "a"}, "a161316161"),  # text key "1": JSON's meaning, not member 1
        ({"2": "aa", "3": "bb"}, "a261326261616133626262"),  # no 0x00 status byte, no CTAP
        ({"signature": 1}, "a1697369676e617475726501"),
        ({"fmt": "none", "authData": "00"}, "a263666d74646e6f6e656861757468446174616230 30".replace(" ", "")),
    ],
)
def test_a_plain_map_is_encoded_as_the_json_it_is(value, expected):
    result = encode_payload_text(json.dumps(value), "cbor")

    assert result["type"] == "CBOR (canonical) (encoded)"
    assert result["data"]["binary"]["hex"] == expected
    assert "ctap" not in result["data"]


@pytest.mark.parametrize(
    "message",
    [b"\x00" + MAKE_CREDENTIAL_RESPONSE, b"\x00" + GET_ASSERTION_RESPONSE, MAKE_CREDENTIAL_RESPONSE],
    ids=["makeCredential", "getAssertion", "makeCredential-without-status-byte"],
)
def test_the_decoders_ctap_view_pasted_into_the_encoder_is_still_a_ctap_message(message):
    # What the UI's Raw view shows as the decoded data is the loop's input.
    decoded = decode_payload_text(message.hex())["data"]

    encoded = encode_payload_text(json.dumps(decoded), "CBOR (canonical)")

    # A response decoded without its status byte is encoded with SUCCESS in front.
    assert encoded["data"]["binary"]["hex"] == (message if message[0] == 0 else b"\x00" + message).hex()
