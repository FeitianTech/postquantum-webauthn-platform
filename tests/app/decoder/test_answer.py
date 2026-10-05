"""``decoder.decode.answer``: the answer the page gets from what a reading returned.

``text.py`` hands ``_prepare_decoder_response`` each reading's result; these give it
results of the shapes the readings return. Its authenticator data view is
``answer_auth_data``'s, the bytes it reads back ``answer_bytes``'s.
"""

import pytest

from server.app.decoder.decode import answer as decode_answer


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

