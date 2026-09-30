"""``decoder.encode.ctap_encode``: the four CTAP messages, each member written under its number.

Format "CBOR (CTAP/WebAuthn Data)" encodes the numbered fields; every optional member a
message has is carried, and the answer shows it by name.
"""
from __future__ import annotations

import json

import pytest

from server.app.decoder.encode import ctap_encode as encode_ctap_encode
from server.app.decoder.encode import text as encode_text
from tests.app.security.ceremony_helpers import b64u

CTAP = "CBOR (CTAP/WebAuthn Data)"
HASH = b64u(b"\x11" * 32)
# authData whose base64url is no hex, so it is read as base64url.
AUTH_DATA = b64u(b"\xab" * 37)
MAKE_CREDENTIAL = {"1": HASH, "2": {"id": "example.com"}, "3": {"id": "AQI"}, "4": [{"type": "public-key", "alg": -7}]}


def _members(value) -> dict:
    (members,) = encode_text.encode_payload_text(json.dumps(value), CTAP)["data"]["ctapDecoded"].values()
    return members


def test_a_make_credential_request_carries_every_optional_member():
    expected = {
        "excludeList": ["0102"],
        "extensions": {"credProtect": 2},
        "options": {"rk": True},
        "pinUvAuthParam": "0a0b",
        "pinUvAuthProtocol": 2,
        "enterpriseAttestation": 1,
        "attestationFormatsPreference": ["packed", "none"],
    }

    members = _members(
        {**MAKE_CREDENTIAL, "5": ["0102"], "6": {"credProtect": 2}, "7": {"rk": True}, "8": "0a0b", "9": "0x02", "10": 1, "11": ["packed", "none"]}
    )

    assert {name: members[name] for name in expected} == expected


@pytest.mark.parametrize(
    ("formats", "error"),
    [("packed", "must be an array of attestation format strings"), ([""], "entry must be a non-empty string")],
)
def test_attestation_formats_preference_is_a_list_of_names(formats, error):
    with pytest.raises(ValueError, match=error):
        _members({**MAKE_CREDENTIAL, "11": formats})


def test_a_get_assertion_request_carries_every_optional_member():
    members = _members({"1": "example.com", "2": HASH, "3": ["0102"], "4": {"hmac-secret": {}}, "5": {"up": False}, "6": "0a0b", "7": 1})

    assert (members["allowList"], members["extensions"], members["options"]) == (["0102"], {"hmac-secret": {}}, {"up": False})
    assert (members["pinUvAuthParam"], members["pinUvAuthProtocol"]) == ("0a0b", 1)


def test_a_make_credential_response_carries_every_optional_member():
    members = _members({"1": "packed", "2": AUTH_DATA, "3": {"alg": -7, "sig": "aa"}, "4": True, "5": "0102", "6": {"x": 1}})

    assert (members["epAtt"], members["largeBlobKey"], members["unsignedExtensionOutputs"]) == (True, "0102", {"x": 1})


def test_a_get_assertion_response_carries_every_optional_member():
    members = _members(
        {"1": {"type": "public-key", "id": "AQI"}, "2": AUTH_DATA, "3": b64u(b"sig"), "4": {"id": "AQI", "name": "a"}, "5": "7",
         "6": "yes", "7": "0102", "8": {"x": 1}}
    )

    assert members["credential"] == {"id": "0102", "type": "public-key"}
    assert members["user"] == {"id": "0102", "name": "a"}
    assert (members["numberOfCredentials"], members["userSelected"], members["largeBlobKey"]) == (7, True, "0102")
    assert members["unsignedExtensionOutputs"] == {"x": 1}


def test_authdata_is_written_with_the_bytes_the_decoder_showed_after_it():
    members = _members({"1": "packed", "2": {"hex": "ab" * 37, "trailingBytesHex": "0102"}})

    assert members["authData"] == "ab" * 37 + "0102"
    with pytest.raises(ValueError, match="authData trailingBytesHex must be hex"):
        _members({"1": "packed", "2": {"hex": "ab" * 37, "trailingBytesHex": "zz"}})


# The format refuses a missing or empty required field before any encoder runs;
# a direct call gives the encoders one.


@pytest.mark.parametrize(
    ("encode", "structure", "error"),
    [
        (encode_ctap_encode._encode_make_credential_request,
         {"clientDataHash": "00", "rp": {"id": "example.com"}, "user": {"id": "00"}}, "requires pubKeyCredParams"),
        (encode_ctap_encode._encode_get_assertion_request, {"rpId": "", "clientDataHash": "00"}, "rpId must be a non-empty string"),
        (encode_ctap_encode._encode_make_credential_response, {"fmt": "", "authData": "00"}, "fmt must be a non-empty string"),
        (encode_ctap_encode._encode_get_assertion_response, {"signature": "00"}, "Unable to interpret authData"),
    ],
)
def test_each_encoder_refuses_a_message_without_its_required_members(encode, structure, error):
    with pytest.raises(ValueError, match=error):
        encode(structure)
