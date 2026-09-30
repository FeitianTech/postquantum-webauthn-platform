"""``decoder.decode.answer``: the answer the page gets from what a reading returned.

``text.py`` hands ``_prepare_decoder_response`` each reading's result; these give it
results of the shapes the readings return, and the byte fields the answer reads back.
"""
import base64
import hashlib

import cbor2
import pytest

from server.app.decoder.decode import answer as decode_answer


def _build_authenticator_data_bytes() -> bytes:
    rp_id_hash = hashlib.sha256(b"example.com").digest()
    flags = bytes([0x45])  # UP + UV + AT
    sign_count = (7).to_bytes(4, "big")

    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"\x10\x20\x30\x40"
    credential_length = len(credential_id).to_bytes(2, "big")
    cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})

    return rp_id_hash + flags + sign_count + aaguid + credential_length + credential_id + cose_key


def _build_attestation_object_bytes() -> tuple[bytes, bytes]:
    from fido2.cose import CoseKey
    from fido2.webauthn import (
        AttestationObject,
        AttestedCredentialData,
        AuthenticatorData,
    )

    credential_id = b"decode-edge-cred"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x03" * 32, -3: b"\x04" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        11,
        credential_data,
    )
    attestation = AttestationObject.create("none", auth_data, {})
    return bytes(attestation), bytes(auth_data)


def test_build_authenticator_data_payload_falls_back_to_raw_bytes_when_details_absent():
    auth_bytes = _build_authenticator_data_bytes()
    payload = decode_answer._build_authenticator_data_payload(auth_bytes, None, fallback_alg=-7)

    assert payload["rpIdHash"] == hashlib.sha256(b"example.com").hexdigest()
    assert payload["flags"]["UP"] is True
    assert payload["flags"]["AT"] is True
    assert payload["counter"] == 7
    assert payload["credential"]["credentialIdLength"] == "0004"
    assert payload["credential"]["credentialId"] == "10203040"
    assert payload["credential"]["publicKey"]["alg"] == "ES256 (ECDSA)"


def test_extract_authenticator_bytes_from_attestation_parses_valid_object_and_handles_invalid():
    attestation_bytes, auth_data_bytes = _build_attestation_object_bytes()
    attestation_entry = {"raw": base64.b64encode(attestation_bytes).decode("ascii")}

    extracted = decode_answer._extract_authenticator_bytes_from_attestation(attestation_entry)
    assert extracted == auth_data_bytes

    assert decode_answer._extract_authenticator_bytes_from_attestation({"raw": "%%%%"}) is None


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


def test_flags_the_details_name_win_over_their_bits():
    named = {
        "userPresent": False, "userVerified": False, "backupEligible": True,
        "backupState": True, "attestedCredentialData": False, "extensionData": True,
    }

    flags = decode_answer._build_flag_payload(named, 0x45)

    assert flags == {"bin": "01000101", "hex": "45", "raw": "45", "UP": False, "UV": False, "BE": True, "BS": True, "AT": False, "ED": True}


def test_authenticator_data_details_without_flags_or_bytes_show_no_flags():
    assert _answer(format="Authenticator data (binary)", decoded={"signCount": 3})["data"] == {"counter": 3}


def test_authenticator_data_too_short_for_flags_shows_none():
    assert decode_answer._build_authenticator_data_payload(b"\x00" * 33, None) == {"raw": "00" * 33, "rpIdHash": "00" * 32}


def test_attested_credential_details_are_shown_beside_what_the_bytes_say():
    credential = decode_answer._build_credential_payload(
        {"credentialId": {"hex": "aabb", "length": "len-as-text"}, "publicKey": "not-a-mapping"},
        b"\x00" * 38,
        None,
    )

    assert credential == {"raw": "00", "credentialIdLength": "len-as-text", "credentialId": "aabb"}


def test_client_data_is_shown_from_its_details_and_an_unnamed_challenge_as_given():
    assert decode_answer._convert_client_data_entry("not-a-map") == {}
    assert decode_answer._convert_client_data_entry({"details": "not-a-map"}) == {}
    assert decode_answer._convert_client_data_entry(
        {"details": {"type": "webauthn.create", "challenge": {"nested": "value"}}}
    ) == {"type": "webauthn.create", "challenge": {"nested": "value"}}
    assert decode_answer._convert_client_data_entry(
        {"details": {"type": "webauthn.get", "challenge": {"base64url": "AQID"}, "crossOrigin": 1}}
    ) == {"type": "webauthn.get", "crossOrigin": 1, "challenge": "AQID"}


def test_a_credentials_authenticator_data_is_read_from_its_attestation_object_when_it_has_none():
    attestation_bytes, auth_data_bytes = _build_attestation_object_bytes()
    raw = base64.b64encode(attestation_bytes).decode("ascii")

    assert decode_answer._extract_authenticator_bytes({"attestationObject": {"raw": raw}}) == auth_data_bytes
    assert decode_answer._extract_authenticator_bytes("not-a-mapping", {"raw": raw}) == auth_data_bytes
    assert decode_answer._extract_authenticator_bytes({"authenticatorData": {"hex": "aa"}}, {"raw": raw}) == b"\xaa"


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"binary": {"hex": "AABB"}}, b"\xaa\xbb"),
        ({"raw": "AQI"}, b"\x01\x02"),
        ({"hex": "ZZ", "raw": "%%%%"}, None),
        ("not-a-mapping", None),
    ],
)
def test_a_fields_bytes_are_its_hex_or_its_base64url(entry, expected):
    assert decode_answer._extract_bytes_from_binary(entry) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # {"authData": h'1122'}, as standard base64 with padding and spaces.
        (" oWhhdXRoRGF0YUIRIg== ", b"\x11\x22"),
        # 0x01 0x02 is CBOR, but not a map with authData.
        ("AQI=", None),
    ],
)
def test_an_attestation_objects_authenticator_data_is_its_auth_data_bytes(raw, expected):
    assert decode_answer._extract_authenticator_bytes_from_attestation({"raw": raw}) == expected


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


@pytest.mark.parametrize(
    ("details", "credential"),
    [
        ({"aaguid": "uuid-only", "credentialId": "not-a-mapping"}, {"aaguid": {"uuid": "uuid-only"}}),
        ({"aaguidHex": "00" * 16, "credentialId": {"hex": "aa", "length": None}}, {"aaguid": {"raw": "00" * 16}, "credentialId": "aa"}),
    ],
)
def test_attested_credential_details_show_only_the_parts_they_have(details, credential):
    assert decode_answer._build_credential_payload(details, None) == credential


def test_a_field_with_an_empty_hex_is_read_from_its_base64url():
    assert decode_answer._extract_bytes_from_binary({"binary": {"hex": ""}, "raw": "AQI"}) == b"\x01\x02"
