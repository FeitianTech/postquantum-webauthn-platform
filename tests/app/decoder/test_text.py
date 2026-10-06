"""Tests of text behavior."""

from __future__ import annotations

import json

import cbor2
import pytest

from server.app.decoder.decode import text as decode_text
from server.app.decoder.decode.text import decode_payload_text
from tests.app.core.codec_examples import PLAIN_TEXT
from tests.app.decoder.credential_bytes import (
    _build_attestation_and_auth_data,
    _build_attestation_object,
)
from tests.app.security.ceremony_helpers import b64u


def test_decode_public_key_credential_preserves_key_fields_and_extensions():
    raw_id = b"codec-public-key-cred"
    attestation_object = _build_attestation_object(counter=3, credential_id=raw_id)
    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": "AQID",
            "origin": "https://example.com",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    credential = {
        "id": b64u(raw_id),
        "rawId": b64u(raw_id),
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "transports": ["internal", "hybrid"],
        "clientExtensionResults": {"credProps": {"rk": True}},
        "response": {
            "attestationObject": b64u(bytes(attestation_object)),
            "clientDataJSON": b64u(client_data_json),
        },
    }

    decoded = decode_text.decode_payload_text(json.dumps(credential))

    assert decoded["success"] is True
    assert decoded["type"] == "PublicKeyCredential"

    payload = decoded["data"]
    assert payload["credential"]["authenticatorAttachment"] == "platform"
    assert payload["credential"]["transports"] == ["internal", "hybrid"]
    assert payload["clientExtensionResults"]["credProps"]["rk"] is True
    assert payload["attestationObject"]["fmt"] == "none"
    assert payload["clientDataJSON"]["type"] == "webauthn.create"
    assert payload["authenticatorData"]["counter"] == 3


def test_plain_english_text_is_not_reported_as_decoded_cbor():
    with pytest.raises(ValueError):
        decode_text.decode_payload_text(PLAIN_TEXT)


def test_decode_payload_text_json_public_key_credential_and_cbor_roundtrip():
    attestation_bytes, _auth_data_bytes = _build_attestation_and_auth_data()
    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": "AQID",
            "origin": "https://example.com",
        }
    ).encode("utf-8")

    credential = {
        "id": b64u(b"cred-id"),
        "rawId": b64u(b"cred-id"),
        "type": "public-key",
        "response": {
            "attestationObject": b64u(attestation_bytes),
            "clientDataJSON": b64u(client_data_json),
        },
    }

    decoded_credential = decode_text.decode_payload_text(json.dumps(credential))
    assert decoded_credential["success"] is True
    assert decoded_credential["type"] == "PublicKeyCredential"
    assert decoded_credential["data"]["attestationObject"]["fmt"] in {
        "none",
        "packed",
    }

    cbor_payload = cbor2.dumps({1: b"\x00" * 32, 2: "example.com"})
    decoded_cbor = decode_text.decode_payload_text(b64u(cbor_payload))
    assert decoded_cbor["success"] is True
    assert decoded_cbor["type"].startswith("CBOR")
    assert "decodedValue" in decoded_cbor["data"]


def test_a_bare_map_of_a_make_credential_request_is_shown_as_one():
    value = {
        1: b"\x11" * 32,
        2: {"id": "example.com", "name": "Example"},
        3: {"id": b"\x01", "name": "user", "displayName": "User"},
        4: [{"type": "public-key", "alg": -7}],
    }

    mapped = decode_payload_text(cbor2.dumps(value).hex())["data"]["ctapDecoded"]["makeCredentialRequest"]

    assert mapped["1 (clientDataHash)"] == (b"\x11" * 32).hex()
    assert mapped["2 (rp)"]["id"] == "example.com"
