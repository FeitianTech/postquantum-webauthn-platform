"""``decoder.encode.ctap_numeric``: the CTAP message a JSON document's numbered fields make.

Format "CBOR (CTAP/WebAuthn Data)" looks for the object whose members are numbered
("1", "0x02", "02 (clientDataHash)"), wherever it sits, and names the message its
fields make -- or says which field keeps it from being one.
"""

from __future__ import annotations

import json

import pytest

from server.app.decoder.encode import ctap_numeric as encode_ctap_numeric
from server.app.decoder.encode import text as encode_text
from tests.app.security.ceremony_helpers import b64u

CTAP = "CBOR (CTAP/WebAuthn Data)"
CLIENT_DATA_HASH = b64u(b"\x11" * 32)


def _encode(value):
    return encode_text.encode_payload_text(json.dumps(value), CTAP)


def _message(value) -> str:
    (message,) = _encode(value)["data"]["ctapDecoded"]
    return message


@pytest.mark.parametrize(
    ("value", "message"),
    [
        # Numbered fields beside members that are not.
        (
            {
                "ignored": "value",
                "1": b64u(b"\x01" * 32),
                "2": {"id": "example.com", "name": "Example"},
                "3": {"id": b64u(b"user-id"), "name": "alice"},
                "4": [{"type": "public-key", "alg": -7}],
            },
            "makeCredentialRequest",
        ),
        # Labelled numbers, in an object further in.
        (
            {"bad": {"field": "value"}, "nested": {"01 (rpId)": "example.com", "02 (clientDataHash)": CLIENT_DATA_HASH}},
            "getAssertionRequest",
        ),
        # Members that name no number are passed over.
        ({"0xzz": 1, "   ": 2, "1": "example.com", "2": CLIENT_DATA_HASH}, "getAssertionRequest"),
    ],
)
def test_the_numbered_fields_are_found_and_the_message_they_make_named(value, message):
    assert _message(value) == message


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ("plain", "Unable to locate CTAP/WebAuthn numeric-keyed fields"),
        ({}, "Unable to locate CTAP/WebAuthn numeric-keyed fields"),
        ({"01": "fmt-only", "nonNumericKey": True}, r"Missing field 0x02 \(authData/clientDataHash/rp\)"),
        ({"2": "not-bytes", "3": b64u(b"sig")}, r"Field 0x02 \(authData\) must be binary data for GetAssertion response"),
        ({"2": b64u(b"\xaa" * 37)}, r"Missing field 0x01"),
        ({"1": b64u(b"\xbb" * 32), "2": "not-an-object"}, r"Field 0x02 \(rp\) must be an object for MakeCredential request"),
        ({"1": "packed", "2": "not-bytes"}, r"Field 0x02 \(authData/clientDataHash\) must be binary data"),
        ({"1": "packed", "2": b64u(b"\x11" * 20)}, "length is not valid for CTAP/WebAuthn data"),
        ({"1": 5, "2": b64u(b"\xcc" * 32)}, "Unable to classify CTAP/WebAuthn data"),
        ({"1": "a", "01": "b", "2": CLIENT_DATA_HASH}, "Duplicate field 0x01 detected"),
    ],
)
def test_fields_that_make_no_message_are_refused_saying_which(value, error):
    with pytest.raises(ValueError, match=error):
        _encode(value)


def test_a_field_the_message_does_not_name_is_kept_with_its_nested_names_read():
    extra = {" 1 (alpha) ": {"2 (beta)": {"bytes": [1, 2]}}, "": "blank-key", "items": [{"3 (gamma)": "x"}], "7 ( )": 1}

    decoded = _encode({"1": "example.com", "2": CLIENT_DATA_HASH, "20": extra})["data"]["ctapDecoded"]

    assert decoded["getAssertionRequest"]["20"] == {"alpha": {"beta": "0102"}, "": "blank-key", "items": [{"gamma": "x"}], "7": 1}


# What JSON text cannot hold -- an object inside itself, a negative or non-text key --
# only a direct call gives the extractor.


def test_an_object_met_again_is_not_searched_twice():
    loop: dict[str, object] = {}
    loop["self"] = loop

    numeric_map, message = encode_ctap_numeric._extract_ctap_numeric_payload([loop, {"1": "example.com", "2": CLIENT_DATA_HASH}])

    assert (message, numeric_map[1]) == ("getAssertionRequest", "example.com")


def test_a_field_number_is_non_negative_and_a_key_of_another_kind_names_none():
    with pytest.raises(ValueError, match="must be non-negative"):
        encode_ctap_numeric._coerce_ctap_numeric_key(-1)

    assert encode_ctap_numeric._coerce_ctap_numeric_key(object()) is None
    with pytest.raises(ValueError, match="at least one CTAP field"):
        encode_ctap_numeric._classify_ctap_numeric_mapping({})
    assert encode_ctap_numeric._normalize_ctap_extra_value({9: "numeric-key"}) == {"9": "numeric-key"}


def test_classify_ctap_numeric_mapping_requires_field_two():
    with pytest.raises(ValueError, match=r"Missing field 0x02"):
        encode_ctap_numeric._classify_ctap_numeric_mapping({1: "example.com"})


def test_classify_ctap_numeric_mapping_rejects_short_auth_data_for_signature_response():
    with pytest.raises(
        ValueError,
        match=r"must contain authenticator data for GetAssertion response",
    ):
        encode_ctap_numeric._classify_ctap_numeric_mapping(
            {
                1: "credential",
                2: b"\x00" * 36,
                3: b"\x01" * 64,
            }
        )


def test_classify_ctap_numeric_mapping_uses_field_two_length_boundaries_for_string_field_one():
    get_assertion_request = encode_ctap_numeric._classify_ctap_numeric_mapping(
        {
            1: "example.com",
            2: b"\x00" * 32,
        }
    )
    assert get_assertion_request == "getAssertionRequest"

    make_credential_response = encode_ctap_numeric._classify_ctap_numeric_mapping(
        {
            1: "example.com",
            2: b"\x00" * 37,
        }
    )
    assert make_credential_response == "makeCredentialResponse"

    with pytest.raises(ValueError, match=r"length is not valid"):
        encode_ctap_numeric._classify_ctap_numeric_mapping(
            {
                1: "example.com",
                2: b"\x00" * 33,
            }
        )


def test_classify_ctap_numeric_mapping_requires_exact_client_data_hash_length_for_make_credential_request():
    with pytest.raises(
        ValueError,
        match=r"clientDataHash\) must be exactly 32 bytes",
    ):
        encode_ctap_numeric._classify_ctap_numeric_mapping(
            {
                1: b"\x01" * 31,
                2: {"id": "example.com", "name": "Example"},
            }
        )
