"""``webauthn.attestation.aaguid``: an AAGUID's spellings, credProtect's names and minPinLength."""
from __future__ import annotations

import math

import pytest

from server.app.webauthn.attestation import aaguid as attestation_aaguid

GUID = "00112233-4455-6677-8899-aabbccddeeff"
HEX = "00112233445566778899aabbccddeeff"


@pytest.mark.parametrize(
    ("value", "label"),
    [
        (1, "userVerificationOptional"),
        (2, "userVerificationOptionalWithCredentialIDList"),
        (3, "userVerificationRequired"),
        # WebAuthn's spelling of the second is read as fido2's.
        ("userVerificationOptionalWithCredentialIdList", "userVerificationOptionalWithCredentialIDList"),
        # Anything else is shown as given.
        ("userVerificationRequired", "userVerificationRequired"),
        (0, 0),
        (4, 4),
        (None, None),
    ],
)
def test_a_cred_protect_policy_is_named_for_its_number(value, label):
    assert attestation_aaguid.describe_cred_protect(value) == label


def test_the_extension_summary_names_the_cred_protect_policy_beside_it():
    summary = attestation_aaguid.summarize_authenticator_extensions({"credProtect": 2, "hmac-secret": True})

    assert summary == {
        "credProtect": 2,
        "credProtectLabel": "userVerificationOptionalWithCredentialIDList",
        "hmac-secret": True,
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, 0), (7, 7), (3.9, 3), (" 42 ", 42), (-1, None), (True, None), (-0.5, None), (math.inf, None),
     (math.nan, None), ("", None), ("  ", None), ("-3", None), ("not-int", None), ([4], None)],
)
def test_a_non_negative_integer_is_read_from_a_number_or_its_text(value, expected):
    assert attestation_aaguid.coerce_non_negative_int(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(GUID, HEX), (GUID.upper(), HEX), (HEX, HEX), ("0011", None), ("not an aaguid", None), (123, None)],
)
def test_an_aaguid_string_is_its_32_hex_digits_in_lower_case(value, expected):
    assert attestation_aaguid.normalize_aaguid_string(value) == expected


@pytest.mark.parametrize(
    "value",
    [bytes.fromhex(HEX), GUID, {"hex": GUID}, {"raw": HEX}, {"hex": "zz", "value": GUID.upper()}],
)
def test_an_aaguid_is_spelled_as_hex_and_as_a_guid(value):
    container = {"aaguid": value}

    attestation_aaguid.augment_aaguid_fields(container)

    assert container == {"aaguid": HEX, "aaguidHex": HEX, "aaguidRaw": HEX, "aaguidGuid": GUID}


def test_bytes_that_are_not_an_aaguids_length_have_no_guid_spelling():
    container = {"aaguid": b"\x01\x02\x03\x04", "aaguidGuid": "stale"}

    attestation_aaguid.augment_aaguid_fields(container)

    assert container == {"aaguid": "01020304", "aaguidHex": "01020304", "aaguidRaw": "01020304"}


@pytest.mark.parametrize("value", ["invalid", {"raw": "not-aaguid"}, 5])
def test_an_unreadable_aaguid_loses_its_stale_spellings(value):
    container = {"aaguid": value, "aaguidHex": "stale", "aaguidGuid": "stale", "aaguidRaw": "stale"}

    attestation_aaguid.augment_aaguid_fields(container)

    assert container == {"aaguid": value}


def test_a_container_that_cannot_be_changed_is_left_alone():
    container = ("aaguid", HEX)

    attestation_aaguid.augment_aaguid_fields(container)

    assert container == ("aaguid", HEX)


@pytest.mark.parametrize(
    ("results", "expected"),
    [
        ({"minPinLength": 6}, 6),
        ({"minPinLength": "8"}, 8),
        ({"minPinLength": {"minPinLength": 4}}, 4),
        ({"minPinLength": {"minimumPinLength": "9"}}, 9),
        ({"minPinLength": {"value": 10}}, 10),
        ({"minPinLength": {"value": ""}}, None),
        ({"minPinLength": -1}, None),
        ({}, None),
        (None, None),
    ],
)
def test_min_pin_length_is_read_from_the_output_or_a_mapping_around_it(results, expected):
    assert attestation_aaguid.extract_min_pin_length(results) == expected
