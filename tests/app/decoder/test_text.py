"""Tests of text behavior."""

from __future__ import annotations

import json

import pytest

from server.app.decoder.decode import text as decode_text
from tests.app.core.codec_examples import PLAIN_TEXT
from tests.app.decoder.credential_bytes import _build_attestation_object
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
