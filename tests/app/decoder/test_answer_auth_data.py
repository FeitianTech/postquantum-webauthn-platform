"""``decoder.decode.answer_auth_data``: authenticator data as the decoder's answer shows it,
from the decoded details where a reading gave them, else from the bytes."""
import hashlib

import cbor2
import pytest

from server.app.decoder.decode import answer_auth_data


def _build_authenticator_data_bytes() -> bytes:
    rp_id_hash = hashlib.sha256(b"example.com").digest()
    flags = bytes([0x45])  # UP + UV + AT
    sign_count = (7).to_bytes(4, "big")

    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"\x10\x20\x30\x40"
    credential_length = len(credential_id).to_bytes(2, "big")
    cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})

    return rp_id_hash + flags + sign_count + aaguid + credential_length + credential_id + cose_key


def test_build_authenticator_data_payload_falls_back_to_raw_bytes_when_details_absent():
    auth_bytes = _build_authenticator_data_bytes()
    payload = answer_auth_data.build_authenticator_data_payload(auth_bytes, None, fallback_alg=-7)

    assert payload["rpIdHash"] == hashlib.sha256(b"example.com").hexdigest()
    assert payload["flags"]["UP"] is True
    assert payload["flags"]["AT"] is True
    assert payload["counter"] == 7
    assert payload["credential"]["credentialIdLength"] == "0004"
    assert payload["credential"]["credentialId"] == "10203040"
    assert payload["credential"]["publicKey"]["alg"] == "ES256 (ECDSA)"


def test_flags_the_details_name_win_over_their_bits():
    named = {
        "userPresent": False, "userVerified": False, "backupEligible": True,
        "backupState": True, "attestedCredentialData": False, "extensionData": True,
    }

    flags = answer_auth_data._build_flag_payload(named, 0x45)

    assert flags == {"bin": "01000101", "hex": "45", "raw": "45", "UP": False, "UV": False, "BE": True, "BS": True, "AT": False, "ED": True}


def test_authenticator_data_too_short_for_flags_shows_none():
    assert answer_auth_data.build_authenticator_data_payload(b"\x00" * 33, None) == {"raw": "00" * 33, "rpIdHash": "00" * 32}


def test_attested_credential_details_are_shown_beside_what_the_bytes_say():
    credential = answer_auth_data._build_credential_payload(
        {"credentialId": {"hex": "aabb", "length": "len-as-text"}, "publicKey": "not-a-mapping"},
        b"\x00" * 38,
        None,
    )

    assert credential == {"raw": "00", "credentialIdLength": "len-as-text", "credentialId": "aabb"}


@pytest.mark.parametrize(
    ("details", "credential"),
    [
        ({"aaguid": "uuid-only", "credentialId": "not-a-mapping"}, {"aaguid": {"uuid": "uuid-only"}}),
        ({"aaguidHex": "00" * 16, "credentialId": {"hex": "aa", "length": None}}, {"aaguid": {"raw": "00" * 16}, "credentialId": "aa"}),
    ],
)
def test_attested_credential_details_show_only_the_parts_they_have(details, credential):
    assert answer_auth_data._build_credential_payload(details, None) == credential
