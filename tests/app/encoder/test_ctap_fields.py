"""``decoder.encode.ctap_fields``: how a CTAP field's JSON value is read for encoding.

Numbers may be text in any base ``int(..., 0)`` reads, booleans the words true/yes/1 and
false/no/0; a credential descriptor may be its ID alone; attStmt's ``sig`` and ``x5c`` are bytes.
"""
from __future__ import annotations

import pytest

from server.app.decoder.encode import ctap_fields as encode_ctap_fields
from tests.app.encoder.ctap_answers import encoded_members
from tests.app.security.ceremony_helpers import b64u

HASH = b64u(b"\x11" * 32)
AUTH_DATA = b64u(b"\xab" * 37)
GET_ASSERTION_RESPONSE = {"2": AUTH_DATA, "3": b64u(b"sig")}
MAKE_CREDENTIAL = {"1": HASH, "2": {"id": "example.com"}, "3": {"id": "AQI"}, "4": [{"type": "public-key", "alg": -7}]}


@pytest.mark.parametrize(("word", "value"), [(True, True), ("yes", True), ("false", False)])
def test_a_boolean_may_be_a_word(word, value):
    assert encoded_members({**GET_ASSERTION_RESPONSE, "6": word})["userSelected"] is value


@pytest.mark.parametrize(
    ("fields", "error"),
    [
        ({**GET_ASSERTION_RESPONSE, "6": "maybe"}, "userSelected must be a boolean value"),
        ({**GET_ASSERTION_RESPONSE, "6": 5}, "userSelected must be a boolean value"),
        ({**GET_ASSERTION_RESPONSE, "5": True}, "numberOfCredentials must be an integer, not a boolean"),
        ({**MAKE_CREDENTIAL, "9": "x"}, "pinUvAuthProtocol must be an integer value"),
        ({"1": "example.com", "2": HASH, "7": 1.5}, "pinUvAuthProtocol must be an integer value"),
        ({**MAKE_CREDENTIAL, "3": {"id": "AQI", "name": 5}}, "user.name must be a non-empty string"),
        ({"1": "example.com", "2": HASH, "5": None}, r"member 5 \(options\) is null"),
        ({"1": "example.com", "2": HASH, "3": "not-a-list"}, "allowList must be an array of credential descriptors"),
        ({"1": "packed", "2": AUTH_DATA, "3": {"x5c": 5}}, "attStmt.x5c must be an array of certificates"),
    ],
)
def test_a_value_of_the_wrong_kind_is_refused_naming_its_field(fields, error):
    with pytest.raises(ValueError, match=error):
        encoded_members(fields)


def test_a_credential_descriptor_may_be_its_id_or_an_object_with_the_members_it_has():
    descriptors = ["0102", {"type": "public-key", "id": "0304", "transports": ["usb"], "extra": "0506"}, {"id": "0708"}, {"type": "public-key"}]

    members = encoded_members({"1": "example.com", "2": HASH, "3": descriptors})

    assert members["allowList"] == [
        "0102",
        {"id": "0304", "type": "public-key", "extra": "0506", "transports": ["usb"]},
        {"id": "0708"},
        {"type": "public-key"},
    ]


def test_an_attestation_statement_holds_its_signature_certificates_and_other_members():
    members = encoded_members({"1": "packed", "2": AUTH_DATA, "3": {"alg": -7, "sig": "aa", "ver": "2.0", "x5c": ["616263"]}})

    assert members["attStmt"] == {"alg": -7, "sig": "aa", "ver": "2.0", "x5c": ["616263"]}


def test_a_user_keeps_the_members_ctap_names_and_any_other():
    members = encoded_members({**MAKE_CREDENTIAL, "3": {"id": "AQI", "name": "a", "displayName": "b", "icon": None, "extra": "0102"}})

    assert members["user"] == {"id": "0102", "name": "a", "extra": "0102", "displayName": "b"}
    assert encoded_members({**MAKE_CREDENTIAL, "3": {"name": "a"}})["user"] == {"name": "a"}


def test_an_attestation_statement_given_as_bytes_or_nothing_is_kept_as_it_is():
    # A numbered attStmt of bytes reads as a GetAssertion signature, and none is left out:
    # only a direct call gives the reader these.
    assert encode_ctap_fields._encode_attestation_statement(None) is None
    assert encode_ctap_fields._encode_attestation_statement(b"\xaa") == b"\xaa"
