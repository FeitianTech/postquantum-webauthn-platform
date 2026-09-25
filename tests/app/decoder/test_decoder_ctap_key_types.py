"""Only an integer key is a CTAP member: a text "1" or a byte string h'01' is not.

CTAP 2.2 section 6 numbers every command parameter and response member with an
integer map key. A map keyed by the text "2" and "3", or by the byte strings
h'02' and h'03', is some other map; the decoder must not read it as a
getAssertion response, nor label its entries as members.
"""
from __future__ import annotations

import cbor2
import pytest

from server.app.decoder import decode_payload_text
from server.app.decoder.decode import ctap, keys

_AUTH_DATA = bytes(32) + b"\x01" + (5).to_bytes(4, "big")
_SIGNATURE = bytes.fromhex("3006020101020101")
_CLIENT_DATA_HASH = bytes(range(32))


def _decode(message: dict, prefix: str = "00") -> dict:
    return decode_payload_text(prefix + cbor2.dumps(message).hex())


def test_integer_keys_are_a_get_assertion_response():
    result = _decode({2: _AUTH_DATA, 3: _SIGNATURE})

    assert result["type"] == "CBOR (SUCCESS status; GetAssertion response)"
    assert "getAssertionResponse" in result["data"]["ctapDecoded"]


@pytest.mark.parametrize(
    "message",
    [
        {"2": _AUTH_DATA, "3": _SIGNATURE},
        {b"\x02": _AUTH_DATA, b"\x03": _SIGNATURE},
    ],
    ids=["text-keys", "byte-string-keys"],
)
def test_text_or_byte_string_keys_are_not_a_get_assertion_response(message):
    result = _decode(message)

    assert result["type"] == "CBOR (SUCCESS status)"
    assert "ctapDecoded" not in result["data"]
    assert "expandedJson" not in result["data"]
    # Shown as sent: both entries are there, under their own keys.
    assert set(result["data"]["decodedValue"]) == {key.hex() if isinstance(key, bytes) else key for key in message}


@pytest.mark.parametrize(
    "message",
    [
        {"1": "packed", "2": _AUTH_DATA, "3": {"alg": -7, "sig": _SIGNATURE}},
        {b"\x01": "packed", b"\x02": _AUTH_DATA, b"\x03": {"alg": -7, "sig": _SIGNATURE}},
    ],
    ids=["text-keys", "byte-string-keys"],
)
def test_text_or_byte_string_keys_are_not_a_make_credential_response(message):
    result = _decode(message)

    assert "MakeCredential" not in result["type"]
    assert "ctapDecoded" not in result["data"]


def test_text_digit_keys_are_not_a_make_credential_request():
    message = {"1": _CLIENT_DATA_HASH, "2": {"id": "example.com"}, "3": {"id": b"u", "name": "u"}}

    result = decode_payload_text(cbor2.dumps(message).hex())

    assert "MakeCredential" not in result["type"]
    assert "ctapDecoded" not in result["data"]


def test_a_command_byte_labels_only_integer_keys_as_parameters():
    # 0x01 names the request, so the map is read as makeCredential parameters;
    # the text "1" beside the integer 2 is still not clientDataHash.
    message = {"1": _CLIENT_DATA_HASH, 2: {"id": "example.com"}}

    request = _decode(message, prefix="01")["data"]["ctapDecoded"]["makeCredentialRequest"]

    assert "2 (rp)" in request
    # A non-integer key of a CTAP map is shown with its type.
    assert '"1" (text)' in request
    assert "1 (clientDataHash)" not in request


def test_a_byte_string_key_in_a_credential_descriptor_is_not_its_id():
    descriptor = ctap._convert_ctap_credential_descriptor({b"\x01": b"\xaa", "type": "public-key"})

    assert "id" not in descriptor
    assert descriptor["01"] == "aa"
    assert descriptor["type"] == "public-key"


def test_get_mapping_entry_does_not_cross_key_types():
    mapping = {1: "integer", "2": "text", b"\x03": "bytes"}

    assert keys.get_mapping_entry(mapping, 1) == "integer"
    assert keys.get_mapping_entry(mapping, "1") is keys.MISSING
    assert keys.get_mapping_entry(mapping, b"\x01") is keys.MISSING
    assert keys.get_mapping_entry(mapping, 2) is keys.MISSING
    assert keys.get_mapping_entry(mapping, 3) is keys.MISSING
    assert keys.get_mapping_entry(mapping, True) is keys.MISSING


def test_resolve_ctap_label_reads_only_integer_members():
    labels = ctap._GET_ASSERTION_RESPONSE_LABELS

    assert ctap._resolve_ctap_label(labels, 2) == "authData"
    assert ctap._resolve_ctap_label(labels, "2") is None
    assert ctap._resolve_ctap_label(labels, b"\x02") is None


# A CTAP member label applies only to the key type and context the spec defines:
# integer keys in a CTAP message, text keys in a WebAuthn attestation object,
# user entity or credential descriptor.

_RP = {"id": "example.com"}
_USER = {"id": b"\x01", "name": "alice"}


def test_a_text_keyed_attestation_object_after_a_status_byte_is_not_a_ctap_response():
    message = {"fmt": "none", "authData": _AUTH_DATA, "attStmt": {}}

    result = _decode(message)

    assert result["type"] == "CBOR (SUCCESS status)"
    assert "ctapDecoded" not in result["data"]
    assert "expandedJson" not in result["data"]
    # Its text keys are WebAuthn's, and it is interpreted as an attestation object.
    assert result["data"]["attestationStatementDecoded"]["fmt"] == "none"


def test_text_named_members_are_not_a_get_assertion_request():
    message = {"rpId": "example.com", "clientDataHash": _CLIENT_DATA_HASH}

    result = decode_payload_text(cbor2.dumps(message).hex())

    assert result["type"] == "CBOR"
    assert "ctapDecoded" not in result["data"]


def test_a_command_byte_does_not_label_a_text_named_member():
    message = {1: "example.com", 2: _CLIENT_DATA_HASH, "rpId": "other.example"}

    request = _decode(message, prefix="02")["data"]["ctapDecoded"]["getAssertionRequest"]

    assert request["1 (rpId)"] == "example.com"
    assert request['"rpId" (text)'] == "other.example"
    assert "rpId (rpId)" not in request


def test_a_text_named_client_data_hash_gets_no_member_label():
    message = {"clientDataHash": _CLIENT_DATA_HASH, 2: _RP, 3: _USER, 4: []}

    request = _decode(message, prefix="01")["data"]["ctapDecoded"]["makeCredentialRequest"]

    assert request['"clientDataHash" (text)'] == _CLIENT_DATA_HASH.hex()
    assert "clientDataHash (clientDataHash)" not in request


def test_integer_keys_in_a_user_entity_are_not_its_members():
    message = {1: _CLIENT_DATA_HASH, 2: _RP, 3: {1: b"\x01", 2: "alice"}, 4: []}

    user = _decode(message, prefix="01")["data"]["ctapDecoded"]["makeCredentialRequest"]["3 (user)"]

    assert user == {"1": "01", "2": "alice"}


def test_a_user_id_that_is_not_bytes_is_shown_as_sent():
    message = {1: _CLIENT_DATA_HASH, 2: _RP, 3: {"id": "text-id", "name": "alice"}, 4: []}

    user = _decode(message, prefix="01")["data"]["ctapDecoded"]["makeCredentialRequest"]["3 (user)"]

    assert user == {"id": "text-id", "name": "alice"}


def test_integer_keys_in_a_credential_descriptor_are_not_its_members():
    message = {1: "example.com", 2: _CLIENT_DATA_HASH, 3: [{1: b"\xaa", 2: "public-key"}]}

    allow_list = _decode(message, prefix="02")["data"]["ctapDecoded"]["getAssertionRequest"]["3 (allowList)"]

    assert allow_list == [{"1": "aa", "2": "public-key"}]


def test_a_credential_descriptor_id_that_is_not_bytes_is_shown_as_sent():
    message = {1: "example.com", 2: _CLIENT_DATA_HASH, 3: [{"id": "text-id", "type": "public-key"}]}

    allow_list = _decode(message, prefix="02")["data"]["ctapDecoded"]["getAssertionRequest"]["3 (allowList)"]

    assert allow_list == [{"id": "text-id", "type": "public-key"}]


def test_text_keys_named_like_response_members_do_not_name_the_message_a_response():
    message = {1: "example.com", 2: _CLIENT_DATA_HASH, "signature": b"x", "attStmt": {}}

    result = _decode(message, prefix="02")

    assert result["type"] == "CBOR (GET_ASSERTION command; GetAssertion request)"


def test_a_text_keyed_descriptor_and_user_still_read_as_their_members():
    message = {1: {"id": b"\xcc", "type": "public-key"}, 2: _AUTH_DATA, 3: _SIGNATURE, 4: {"id": b"\x01", "name": "bob"}}

    response = _decode(message)["data"]["ctapDecoded"]["getAssertionResponse"]

    assert response["1 (credential)"] == {"id": "cc", "type": "public-key"}
    assert response["4 (user)"] == {"id": "01", "name": "bob"}
