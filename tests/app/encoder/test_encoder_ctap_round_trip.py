"""What the decoder shows for a CTAP map, the encoder turns back into the same bytes.

The encoder used to ignore which kind of CTAP map ``ctapDecoded`` named and
re-classify the fields by key number alone, so a "1 (rpId)" was taken for a
makeCredential response's fmt and a request came back as a response, or not at
all.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from fido2 import cbor
from fido2.webauthn import AuthenticatorData
from server.app.decoder import decode_payload_text, encode_payload_text

_AUTH_DATA = bytes(AuthenticatorData.create(hashlib.sha256(b"example.com").digest(), 0x05, 7))

_MESSAGES = {
    "makeCredentialRequest": b"\x01"
    + cbor.encode(
        {
            1: b"\x11" * 32,
            2: {"id": "example.com", "name": "Example"},
            3: {"id": b"user-1", "name": "alice", "displayName": "Alice"},
            4: [{"alg": -48, "type": "public-key"}, {"alg": -7, "type": "public-key"}],
            5: [{"type": "public-key", "id": b"\x0a\x0b"}],
            7: {"rk": True},
        }
    ),
    "getAssertionRequest": b"\x02"
    + cbor.encode(
        {
            1: "example.com",
            2: b"\x22" * 32,
            3: [{"type": "public-key", "id": b"\x01\x02"}],
            5: {"up": True},
        }
    ),
    "makeCredentialResponse": b"\x00" + cbor.encode({1: "none", 2: _AUTH_DATA, 3: {}}),
    "getAssertionResponse": b"\x00"
    + cbor.encode({1: {"type": "public-key", "id": b"\x01\x02"}, 2: _AUTH_DATA, 3: b"\x30" * 70}),
}


def _encode(body) -> tuple[str, bytes]:
    result = encode_payload_text(json.dumps(body), "cbor")
    return result["type"], bytes.fromhex(result["data"]["binary"]["hex"])


@pytest.mark.parametrize("kind", sorted(_MESSAGES))
def test_the_decoded_ctap_map_encodes_back_to_the_same_bytes(kind):
    raw = _MESSAGES[kind]
    decoded = decode_payload_text(raw.hex())["data"]
    assert kind in decoded["ctapDecoded"]

    encoded_type, encoded = _encode(decoded)

    assert encoded_type.endswith(f"(encoded {kind})")
    assert encoded == raw


@pytest.mark.parametrize("kind", sorted(_MESSAGES))
def test_the_expanded_json_alone_encodes_back_to_the_same_bytes(kind):
    raw = _MESSAGES[kind]
    decoded = decode_payload_text(raw.hex())["data"]

    encoded_type, encoded = _encode({"expandedJson": decoded["expandedJson"], "ctap": decoded["ctap"]})

    assert encoded_type.endswith(f"(encoded {kind})")
    assert encoded == raw


def test_a_numbered_key_matches_a_field_only_under_that_fields_name():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._ctap_key_matches("1 (rpId)", {"1", "rpid", "1 (rpid)"}) is True
    assert encode_module._ctap_key_matches("1 (rpId)", {"1", "fmt", "1 (fmt)"}) is False
    assert encode_module._ctap_key_matches("5 (rpId)", {"1", "rpid", "1 (rpid)"}) is False
    assert encode_module._ctap_key_matches("2 (authData trailing)", {"2", "authdata", "2 (authdata)"}) is False


def test_the_message_ctap_decoded_names_is_the_one_its_members_are_read_as():
    from server.app.decoder import ctap_message

    members = ctap_message.read_members(
        "getAssertionRequest",
        {"1 (rpId)": "example.com", "2 (clientDataHash)": "22" * 32, "5 (options)": {"up": True}},
    )

    assert members == {1: "example.com", 2: b"\x22" * 32, 5: {"up": True}}
