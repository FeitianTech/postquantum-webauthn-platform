"""``decoder.decode.answer``: the answer the page gets from what a reading returned.

``text.py`` hands ``_prepare_decoder_response`` each reading's result; these give it
results of the shapes the readings return. Its authenticator data view is
``answer_auth_data``'s, the bytes it reads back ``answer_bytes``'s.
"""

import base64

import pytest

from server.app.decoder.decode import answer as decode_answer
from tests.app.decoder.credential_bytes import _build_attestation_and_auth_data
from tests.app.security.ceremony_helpers import b64u


def _answer(**result):
    return decode_answer._prepare_decoder_response(result)


def test_a_result_without_a_format_is_decoded_data_showing_what_it_holds():
    assert _answer(decoded={"x": 1})["type"] == "Decoded data"
    assert _answer(decoded={"x": 1})["data"] == {"x": 1}
    assert _answer(binary={"hex": "0102"})["data"] == {"hex": "0102"}
    assert _answer()["data"] == {}


def test_cbor_is_named_by_what_ctap_makes_of_it_each_name_once():
    answer = _answer(
        format="CBOR (strict)",
        decoded={
            "ctap": {"meaning": "MakeCredential request"},
            "ctapDecoded": {"makeCredentialRequest": {"rp": "example.com"}},
            "expandedJson": {"attStmt": {"sig": "aa"}, "signature": "bb"},
        },
        malformed="not a list",
    )

    # Text keys named "attStmt" or "signature" do not make a response of it.
    assert answer["type"] == "CBOR (MakeCredential request)"
    assert answer["malformed"] == []


@pytest.mark.parametrize(
    ("decoded", "data"),
    [({"only": "decoded"}, {"cbor": {"only": "decoded"}}), ([1, 2, 3], {"cbor": [1, 2, 3]})],
)
def test_cbor_the_reading_did_not_name_is_shown_as_it_is(decoded, data):
    assert _answer(format="CBOR", decoded=decoded)["data"] == data


def test_authenticator_data_details_without_bytes_are_shown_as_given():
    answer = _answer(
        format="Authenticator data (binary)",
        decoded={"rpIdHash": "rp-hash", "flags": {"value": "bad"}, "signCount": "not-an-int", "extensions": {"uvm": True}},
    )

    assert answer["data"] == {"rpIdHash": "rp-hash", "counter": "not-an-int", "extensions": {"uvm": True}}


def test_flags_are_read_from_their_details_when_there_are_no_bytes():
    answer = _answer(
        format="Authenticator data (binary)",
        decoded={"flags": {"value": 0x45, "bitfield": "0b01000101", "userPresent": True, "attestedCredentialData": True}},
    )

    assert answer["data"]["flags"] == {
        "bin": "01000101", "hex": "45", "raw": "45", "UP": True, "UV": True, "BE": False, "BS": False, "AT": True, "ED": False,
    }


def test_authenticator_data_details_without_flags_or_bytes_show_no_flags():
    assert _answer(format="Authenticator data (binary)", decoded={"signCount": 3})["data"] == {"counter": 3}


def test_client_data_is_shown_from_its_details_and_an_unnamed_challenge_as_given():
    assert decode_answer._convert_client_data_entry("not-a-map") == {}
    assert decode_answer._convert_client_data_entry({"details": "not-a-map"}) == {}
    assert decode_answer._convert_client_data_entry(
        {"details": {"type": "webauthn.create", "challenge": {"nested": "value"}}}
    ) == {"type": "webauthn.create", "challenge": {"nested": "value"}}
    assert decode_answer._convert_client_data_entry(
        {"details": {"type": "webauthn.get", "challenge": {"base64url": "AQID"}, "crossOrigin": 1}}
    ) == {"type": "webauthn.get", "crossOrigin": 1, "challenge": "AQID"}


def test_a_credential_shows_its_raw_id_as_given_and_leaves_out_what_it_lacks():
    assert _answer(format="PublicKeyCredential (JSON)", decoded={"rawId": "abc", "response": "not-a-mapping"})["data"] == {
        "credential": {"rawId": "abc"}
    }
    assert _answer(format="PublicKeyCredential (JSON)", decoded={"rawId": {"raw": None}, "response": {}})["data"] == {}


@pytest.mark.parametrize(
    ("binary", "attestation"),
    [
        ({"base64": "AQI="}, {"fmt": "none", "raw": "AQI="}),
        ({"hex": "0102"}, {"fmt": "none"}),
        ("not-a-mapping", {"fmt": "none"}),
    ],
)
def test_an_attestation_object_shows_its_bytes_as_the_reading_gave_them(binary, attestation):
    answer = _answer(format="Attestation object (CBOR)", decoded={"fmt": "none"}, binary=binary)

    assert answer["data"] == {"attestationObject": attestation}


def test_an_attestation_object_with_nothing_readable_shows_nothing():
    assert _answer(format="Attestation object (CBOR)", decoded={})["data"] == {}
    assert _answer(format="Attestation object (CBOR)", decoded={"fmt": "none", "raw": "AQI="})["data"] == {
        "attestationObject": {"fmt": "none", "raw": "AQI="}
    }


def test_a_certificate_result_without_a_certificate_shows_nothing():
    assert _answer(format="X.509 certificate (DER)", decoded={})["data"] == {}


def test_build_decoder_payload_for_cbor_deduplicates_qualifiers_and_normalizes_malformed():
    payload = decode_answer._build_decoder_payload(
        {
            "format": "CBOR",
            "decoded": {
                "ctap": {"meaning": "AuthenticatorGetAssertion command"},
                "ctapDecoded": {
                    "getAssertionRequest": {"rpId": "example.com"},
                    "getAssertionResponse": {"signature": "deadbeef"},
                },
                "expandedJson": {
                    "signature": "deadbeef",
                },
            },
            "malformed": "not-a-list",
        }
    )

    assert payload["success"] is True
    assert payload["type"].startswith("CBOR (")
    assert payload["type"].count("GetAssertion response") == 1
    assert payload["type"].count("GetAssertion request") == 1
    assert payload["malformed"] == []


def test_json_cbor_and_unrecognised_results_become_their_data():
    assert decode_answer._convert_result_to_data("JSON", {"decoded": {"a": 1}}) == {
        "json": {"a": 1}
    }

    cbor_payload = decode_answer._convert_result_to_data(
        "CBOR",
        {
            "decoded": {
                "ctapDecoded": {1: {"sig": b"\x01\x02"}},
                "expandedJson": {"attStmt": {"sig": b"\x03\x04"}},
                "decodedValue": {"k": "v"},
                "ctap": {"code": 2},
            }
        },
    )
    assert "ctapDecoded" in cbor_payload
    assert "expandedJson" in cbor_payload
    assert "decodedValue" in cbor_payload
    assert cbor_payload["ctap"]["code"] == 2

    fallback = decode_answer._convert_result_to_data(
        "Unknown type",
        {"decoded": None, "binary": {"hex": "aabb"}},
    )
    assert fallback == {"hex": "aabb"}


def test_convert_public_key_credential_and_attestation_object_data_paths():
    attestation_bytes, auth_data_bytes = _build_attestation_and_auth_data()
    attestation_b64 = base64.b64encode(attestation_bytes).decode("ascii")

    public_key_result = {
        "decoded": {
            "id": b64u(b"cred"),
            "type": "public-key",
            "response": {
                "attestationObject": {
                    "raw": attestation_b64,
                    "details": {
                        "attestationFormat": "none",
                        "attestationStatement": {"alg": -7},
                        "authenticatorData": {
                            "flags": {"value": 0x41, "userPresent": True, "attestedCredentialData": True},
                            "signCount": 2,
                        },
                    },
                },
                "clientDataJSON": {
                    "details": {
                        "type": "webauthn.create",
                        "challenge": "AQID",
                        "origin": "https://example.com",
                        "crossOrigin": False,
                    }
                },
            },
            "clientExtensionResults": {"credProps": {"rk": True}},
        }
    }

    converted_public = decode_answer._convert_result_to_data("PublicKeyCredential", public_key_result)
    assert converted_public["credential"]["type"] == "public-key"
    assert converted_public["attestationObject"]["fmt"] == "none"
    assert converted_public["clientExtensionResults"]["credProps"]["rk"] is True

    attestation_result = {
        "decoded": {
            "attestationFormat": "packed",
            "attestationStatement": {"alg": -7},
            "extensions": {"credProps": {"rk": True}},
            "authenticatorData": {
                "flags": {
                    "value": 0x41,
                    "userPresent": True,
                    "attestedCredentialDataIncluded": True,
                },
                "signCount": 2,
            },
        },
        "binary": {"base64": attestation_b64},
    }

    converted_attestation = decode_answer._convert_result_to_data("Attestation object", attestation_result)
    assert converted_attestation["attestationObject"]["raw"] == attestation_b64
    assert converted_attestation["extensions"]["credProps"]["rk"] is True
    assert converted_attestation["authenticatorData"]["counter"] == 2
    assert converted_attestation["authenticatorData"]["flags"]["AT"] is True


def test_convert_authenticator_clientdata_and_certificate_result_paths():
    _attestation_bytes, auth_data_bytes = _build_attestation_and_auth_data()

    auth_result = {
        "decoded": {
            "flags": {"value": 0x41, "userPresent": True, "attestedCredentialDataIncluded": True},
            "signCount": 2,
        },
        "binary": {"hex": auth_data_bytes.hex()},
    }
    converted_auth = decode_answer._convert_result_to_data("Authenticator data", auth_result)
    assert converted_auth["raw"] == auth_data_bytes.hex()
    assert converted_auth["counter"] == 2

    client_result = {
        "decoded": {
            "type": "webauthn.get",
            "challenge": "AQID",
            "origin": "https://example.com",
            "crossOrigin": True,
        }
    }
    converted_client = decode_answer._convert_result_to_data("WebAuthn client data", client_result)
    assert converted_client["type"] == "webauthn.get"
    assert converted_client["crossOrigin"] is True

    certificate_bytes = b"\x30\x82\x01\x00"
    certificate_result = {
        "decoded": {
            "certificates": [
                {
                    "derBase64": base64.b64encode(certificate_bytes).decode("ascii"),
                    "pem": "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----",
                }
            ]
        }
    }
    converted_certificate = decode_answer._convert_result_to_data(
        "X.509 certificate", certificate_result
    )
    assert converted_certificate["certificates"]
    assert converted_certificate["certificates"][0]["raw"] == certificate_bytes.hex()


def test_decoder_response_keeps_json_type_and_success():
    prepared = decode_answer._prepare_decoder_response({'format': 'JSON', 'decoded': {'ok': True}})
    assert prepared['success'] is True
    assert prepared['type'] == 'JSON'
