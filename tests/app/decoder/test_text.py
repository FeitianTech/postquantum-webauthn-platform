"""Tests of text behavior."""

from __future__ import annotations

import base64
import json

import cbor2
import pytest

from server.app.decoder import item_budget
from server.app.decoder.decode import cbor_parser, json_input
from server.app.decoder.decode import text as decode_text
from server.app.decoder.decode.text import decode_payload_text
from tests.app.core.codec_examples import PLAIN_TEXT
from tests.app.decoder.credential_bytes import (
    _build_attestation_and_auth_data,
    _build_attestation_object,
)
from tests.app.security.ceremony_helpers import b64u
from tests.app.unreachable import unreachable_after


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


_BYTE_STRINGS = bytes([0x98, 12]) + b"\x41\x00" * 12  # an array of twelve 1-byte byte strings: 13 items
_KEYS_IN_KEYS = b"\xa1" * 8 + b"\x43abc" + b"\x00" * 8  # {{{h'616263': 0}: 0}: 0}, 8 deep: each key spelled


@pytest.mark.parametrize(
    ("text", "lenient", "max_items", "refusal"),
    [
        (_BYTE_STRINGS.hex(), False, 10, item_budget.ItemLimitError),
        (base64.b64encode(_BYTE_STRINGS).decode(), True, 10, item_budget.ItemLimitError),
        (json.dumps(list(range(12))), False, 10, item_budget.ItemLimitError),
        (_KEYS_IN_KEYS.hex(), False, 20_000, item_budget.SpellingLimitError),
        ("a20102", False, 20_000, cbor_parser._CborDecodingError),
        ("[" * 70 + "]" * 70, False, 20_000, json_input.JsonDepthError),
        ('{"a": NaN}', False, 20_000, json_input.JsonConstantError),
        ("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----", False, 20_000, ValueError),
        ("zz==", False, 20_000, ValueError),
        (_BYTE_STRINGS.hex(), False, 20_000, None),
        (_BYTE_STRINGS[:-1].hex(), True, 20_000, None),
        ('{"a": [1, {"b": 2}], "a": 3}', False, 20_000, None),
    ],
    ids=[
        "items-hex",
        "items-base64-lenient",
        "items-json",
        "spelling",
        "malformed-cbor",
        "json-too-deep",
        "json-nan",
        "malformed-pem",
        "malformed-base64",
        "answered",
        "answered-lenient-with-findings",
        "answered-json-with-a-repeated-key",
    ],
)
def test_a_decode_leaves_nothing_for_the_garbage_collector(monkeypatch, text, lenient, max_items, refusal):
    # What a request read is given back when it ends, refused or answered: a cycle would keep it until
    # a full collection, which a quiet process may never run.
    monkeypatch.setattr(item_budget, "MAX_SPELLING_UNITS", 40)

    assert unreachable_after(lambda: decode_payload_text(text, lenient=lenient, max_items=max_items)) == (0, refusal)
