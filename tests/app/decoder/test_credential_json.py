"""``decoder.decode.credential_json``: a PublicKeyCredential's JSON and its client data, as the decoder reads them."""
from __future__ import annotations

import base64
import json

from server.app.decoder.decode import credential_json
from server.app.decoder.decode.text import decode_payload_text


def test_a_credentials_signature_and_user_handle_are_shown_with_their_bytes():
    result = credential_json.decode_public_key_credential(
        {"id": "credential-id", "type": "public-key", "response": {"signature": "qrs", "userHandle": "AQI"}}
    )

    response = result["decoded"]["response"]
    assert response["signature"]["binary"]["hex"] == "aabb"
    assert response["userHandle"]["binary"]["hex"] == "0102"
    assert "rawJson" not in result["decoded"]


def test_a_credential_with_authenticator_data_and_no_attestation_is_an_authentication():
    auth_data = base64.b64encode(bytes(37)).decode("ascii")

    result = credential_json.decode_public_key_credential(
        {"id": "credential-id", "type": "public-key", "response": {"authenticatorData": auth_data}}
    )

    assert result["format"] == "PublicKeyCredential (authentication)"
    assert result["decoded"]["response"]["authenticatorData"]["details"]["signCount"] == 0


def test_client_data_shows_its_fields_and_a_challenge_that_is_no_binary_as_given():
    details = credential_json.build_client_data_details(
        {
            "type": "webauthn.create",
            "challenge": "not valid binary!",
            "origin": "https://example.com",
            "crossOrigin": 1,
            "tokenBinding": {"status": "present"},
        },
        raw_text="raw-json-text",
    )

    assert details["challenge"] == {"raw": "not valid binary!"}
    assert (details["crossOrigin"], details["tokenBinding"], details["rawText"]) == (True, {"status": "present"}, "raw-json-text")


def test_client_data_without_a_challenge_says_so():
    details = credential_json.build_client_data_details({"type": "x", "origin": "https://e"})

    assert details["challenge"] is None
    assert "rawText" not in details


def test_client_data_fido2_cannot_read_is_still_shown_as_its_json():
    text = json.dumps({"type": "webauthn.get", "challenge": "AQID"})

    details = credential_json.describe_client_data_from_bytes(text.encode("utf-8"))

    assert details["type"] == "webauthn.get"
    assert details["challenge"]["hex"] == "010203"
    assert details["rawText"] == text
    assert "origin" not in details


def test_a_credential_whose_attestation_object_is_an_empty_map_interprets_nothing():
    # "oA" is the base64url of 0xa0, an empty CBOR map: no fmt, no authData.
    credential = {"id": "x", "type": "public-key", "response": {"attestationObject": "oA"}}

    data = decode_payload_text(json.dumps(credential))["data"]

    assert set(data) == {"credential", "attestationObject"}
    assert data["attestationObject"]["parseError"]["reason"].startswith("An attestation object has a text fmt")


def test_client_data_json_is_shown_as_client_data():
    raw = json.dumps({"type": "webauthn.get", "challenge": "AQID", "origin": "https://example.com"})

    result = credential_json.decode_json_object(json.loads(raw), raw_text=raw)

    assert result["format"] == "WebAuthn client data (JSON)"
    assert result["inputEncoding"] == "json"
    assert result["decoded"]["challenge"]["hex"] == "010203"
    assert decode_payload_text(raw)["type"] == "WebAuthn client data"


def test_json_that_is_no_credential_or_client_data_is_shown_as_json():
    assert credential_json.decode_json_object([1, 2, 3]) == {"format": "JSON", "inputEncoding": "json", "decoded": [1, 2, 3]}
