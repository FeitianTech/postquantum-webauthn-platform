"""``decoder.encode.handlers_cbor``: format CBOR writes a CTAP message only from the decoder's explicit CTAP view.

That view is ``ctapDecoded``, or ``expandedJson`` beside the ``ctap`` framing that names
its message; any other object is a plain map, whatever its keys look like.
"""

from __future__ import annotations

import base64
import json

import pytest

from server.app.decoder.encode import handlers_cbor as encode_handlers_cbor
from server.app.decoder.encode import text as encode_text
from tests.app.security.ceremony_helpers import b64u

MAKE_CREDENTIAL = {
    # A view's members by number, its values in the view's spelling: bytes as hex.
    "1 (clientDataHash)": "11" * 32,
    "2 (rp)": {"id": "example.com", "name": "Example"},
    "3 (user)": {"id": b"user".hex(), "name": "alice", "displayName": "Alice"},
    "4 (pubKeyCredParams)": [{"alg": -7, "type": "public-key"}],
}
GET_ASSERTION = {"1 (rpId)": "example.com", "2 (clientDataHash)": "22" * 32}


def _cbor(value):
    return encode_text.encode_payload_text(json.dumps(value), "CBOR")


def test_a_ctap_decoded_view_is_written_as_its_message_after_its_byte():
    answer = _cbor({"ctap": {"code": 1, "codeHex": "0x01", "kind": "command"}, "ctapDecoded": {"makeCredentialRequest": MAKE_CREDENTIAL}})

    assert answer["type"] == "CBOR (canonical) (encoded makeCredentialRequest)"
    assert answer["data"]["ctap"]["code"] == 1
    assert answer["data"]["binary"]["hex"].startswith("01a4")


def test_expanded_json_is_a_ctap_view_only_beside_the_framing_that_names_it():
    framing = {"code": 2, "codeHex": "0x02", "kind": "command", "message": "getAssertionRequest"}

    framed = _cbor({"expandedJson": GET_ASSERTION, "ctap": framing})
    plain = _cbor({"expandedJson": {"rpId": "example.com"}})

    assert framed["type"] == "CBOR (canonical) (encoded getAssertionRequest)"
    assert plain["type"] == "CBOR (canonical) (encoded)"
    assert "ctap" not in plain["data"]


def test_a_map_with_ctap_member_names_is_still_a_plain_map():
    # A root map with CTAP member names was once read as a makeCredential response.
    answer = _cbor({"fmt": "none", "authData": "00" * 37})

    assert answer["type"] == "CBOR (canonical) (encoded)"
    assert "ctapDecoded" not in answer["data"]
    assert answer["data"]["binary"]["hex"].startswith("a263666d74646e6f6e65")


def test_anything_else_is_written_as_plain_cbor():
    answer = _cbor([1, 2, 3])

    assert answer["type"] == "CBOR (canonical) (encoded)"
    assert answer["data"]["binary"]["hex"] == "83010203"


def test_encode_ctap_webauthn_requires_mandatory_fields_for_make_credential_request():
    client_data_hash = base64.urlsafe_b64encode(b"\x00" * 32).decode("ascii").rstrip("=")

    with pytest.raises(ValueError, match=r"Missing field 0x03 \(user\)"):
        encode_handlers_cbor._encode_ctap_webauthn_value(
            {
                "1": client_data_hash,
                "2": {"id": "example.com", "name": "Example RP"},
            }
        )


def test_encode_ctap_webauthn_rejects_duplicate_fields_after_key_normalization():
    with pytest.raises(ValueError, match=r"Duplicate field 0x01"):
        encode_handlers_cbor._encode_ctap_webauthn_value(
            {
                "1 (clientDataHash)": b64u(b"\x00" * 32),
                "01": b64u(b"\x11" * 32),
                "2": {"id": "example.com", "name": "Example"},
                "3": {
                    "id": b64u(b"user-id"),
                    "name": "user@example.com",
                    "displayName": "User",
                },
                "4": [{"type": "public-key", "alg": -7}],
            }
        )


def test_encode_ctap_webauthn_preserves_unknown_extra_numeric_fields():
    result = encode_handlers_cbor._encode_ctap_webauthn_value(
        {
            "1": "example.com",
            "2": b64u(b"\x22" * 32),
            "42": "debug-metadata",
        }
    )

    assert result["success"] is True
    assert result["type"] == "CBOR (CTAP/WebAuthn Data) (encoded getAssertionRequest)"
    encoded = result["data"]["encodedValue"]
    assert encoded["42"] == "debug-metadata"
    decoded = result["data"]["ctapDecoded"]["getAssertionRequest"]
    assert decoded["42"] == "debug-metadata"
