"""``decoder.decode.answer_bytes``: the bytes the decoder's answer reads back from a reading's entries."""

import base64
import hashlib

import pytest

from server.app.decoder.decode import answer_bytes


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


def test_a_credentials_authenticator_data_is_read_from_its_attestation_object_when_it_has_none():
    attestation_bytes, auth_data_bytes = _build_attestation_object_bytes()
    raw = base64.b64encode(attestation_bytes).decode("ascii")

    assert answer_bytes.extract_authenticator_bytes({"attestationObject": {"raw": raw}}) == auth_data_bytes
    assert answer_bytes.extract_authenticator_bytes("not-a-mapping", {"raw": raw}) == auth_data_bytes
    assert answer_bytes.extract_authenticator_bytes({"authenticatorData": {"hex": "aa"}}, {"raw": raw}) == b"\xaa"


def test_extract_authenticator_bytes_from_attestation_parses_valid_object_and_handles_invalid():
    attestation_bytes, auth_data_bytes = _build_attestation_object_bytes()
    attestation_entry = {"raw": base64.b64encode(attestation_bytes).decode("ascii")}

    extracted = answer_bytes.extract_authenticator_bytes_from_attestation(attestation_entry)
    assert extracted == auth_data_bytes

    assert answer_bytes.extract_authenticator_bytes_from_attestation({"raw": "%%%%"}) is None


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
    assert answer_bytes.extract_bytes_from_binary(entry) == expected


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
    assert answer_bytes.extract_authenticator_bytes_from_attestation({"raw": raw}) == expected


def test_a_field_with_an_empty_hex_is_read_from_its_base64url():
    assert answer_bytes.extract_bytes_from_binary({"binary": {"hex": ""}, "raw": "AQI"}) == b"\x01\x02"


def test_extract_bytes_from_binary_prefers_hex_and_then_base64url_raw():
    assert answer_bytes.extract_bytes_from_binary({"hex": "AA BB"}) == b"\xaa\xbb"

    raw_value = base64.urlsafe_b64encode(b"\x01\x02\x03").decode("ascii").rstrip("=")
    assert answer_bytes.extract_bytes_from_binary({"raw": raw_value}) == b"\x01\x02\x03"
    assert answer_bytes.extract_bytes_from_binary({"raw": ""}) is None
