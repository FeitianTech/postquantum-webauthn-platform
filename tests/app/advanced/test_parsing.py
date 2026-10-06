"""Tests for how the advanced routes read the credentials the page sends back."""

from __future__ import annotations

from server.app.routes.advanced import parsing
from server.app.routes.advanced import parsing as advanced_parsing
from tests.app.security.ceremony_helpers import Authenticator, b64u
from tests.app.storage.credential_seed import sample_public_key_bytes


def test_a_resident_flag_given_as_null_is_read_from_the_next_field_that_gives_one():
    said_by_cred_props = {
        **Authenticator(credential_id=b"\x01" * 32).stored_credential_entry(),
        "resident": None,
        "clientExtensionOutputs": {"credProps": {"rk": True}},
    }
    said_nowhere = {**Authenticator(credential_id=b"\x02" * 32).stored_credential_entry(), "resident": None}

    records = parsing._parse_client_supplied_credentials([said_by_cred_props, said_nowhere])

    assert [record["resident"] for record in records] == [True, False]


def test_an_aaguid_given_as_plain_hex_is_read_as_hex_not_as_base64():
    authenticator = Authenticator(credential_id=b"\x03" * 32, aaguid=bytes.fromhex("00112233445566778899aabbccddeeff"))
    entry = authenticator.stored_credential_entry()
    entry["aaguidHex"] = authenticator.aaguid.hex()
    del entry["aaguid"]

    records = parsing._parse_client_supplied_credentials([entry])

    assert [bytes(record["data"].aaguid) for record in records] == [authenticator.aaguid]


def _valid_credential_entry(*, resident=None, properties=None, algorithm=None):
    entry = {
        "credentialId": b64u(b"credential-id-1"),
        "publicKey": b64u(sample_public_key_bytes()),
        "aaguid": b64u(bytes.fromhex("00112233445566778899aabbccddeeff")),
        "signCount": 7,
    }
    if resident is not None:
        entry["resident"] = resident
    if properties is not None:
        entry["properties"] = properties
    if algorithm is not None:
        entry["algorithm"] = algorithm
    return entry


def test_parse_client_supplied_credentials_skips_entries_missing_required_fields():
    records = advanced_parsing._parse_client_supplied_credentials(
        [
            {"publicKey": b64u(sample_public_key_bytes())},
            {"credentialId": b64u(b"id-only")},
        ]
    )

    assert records == []


def test_parse_client_supplied_credentials_skips_malformed_entries_and_keeps_valid_ones():
    malformed = {
        "credentialId": "g$",
        "publicKey": b64u(sample_public_key_bytes()),
    }
    valid = _valid_credential_entry(resident=True)

    records = advanced_parsing._parse_client_supplied_credentials([malformed, valid])

    assert len(records) == 1
    assert records[0]["resident"] is True


def test_parse_client_supplied_credentials_uses_properties_resident_flag_when_top_level_absent():
    entry = _valid_credential_entry(properties={"residentKey": True})

    records = advanced_parsing._parse_client_supplied_credentials([entry])

    assert len(records) == 1
    assert records[0]["resident"] is True


def test_parse_client_supplied_credentials_prefers_top_level_resident_over_properties():
    entry = _valid_credential_entry(resident=False, properties={"residentKey": True})

    records = advanced_parsing._parse_client_supplied_credentials([entry])

    assert len(records) == 1
    assert records[0]["resident"] is False


def test_parse_client_supplied_credentials_defaults_missing_aaguid_to_zero_bytes():
    entry = _valid_credential_entry()
    entry.pop("aaguid")

    records = advanced_parsing._parse_client_supplied_credentials([entry])

    assert len(records) == 1
    assert len(records[0]["data"].aaguid) == 16


def test_parse_client_supplied_credentials_coerces_named_algorithm_identifier():
    entry = _valid_credential_entry(algorithm="ES256")

    records = advanced_parsing._parse_client_supplied_credentials([entry])

    assert len(records) == 1
    assert records[0]["algorithm"] == -7


def test_parse_client_supplied_credentials_ignores_non_list_and_non_mapping_entries():
    assert advanced_parsing._parse_client_supplied_credentials({"not": "a-list"}) == []

    valid = _valid_credential_entry(resident=True)
    records = advanced_parsing._parse_client_supplied_credentials([1, "x", valid])

    assert len(records) == 1
    assert records[0]["resident"] is True


def test_parse_client_supplied_credentials_derives_resident_from_client_extension_outputs():
    rk_mapping_entry = _valid_credential_entry()
    rk_mapping_entry["clientExtensionOutputs"] = {"credProps": {"rk": True}}

    rk_boolean_entry = _valid_credential_entry()
    rk_boolean_entry["credentialId"] = b64u(b"credential-id-2")
    rk_boolean_entry["clientExtensionOutputs"] = {"credProps": False}

    records = advanced_parsing._parse_client_supplied_credentials(
        [rk_mapping_entry, rk_boolean_entry]
    )

    assert [record["resident"] for record in records] == [True, False]


def test_parse_client_supplied_credentials_uses_property_attachment_and_defaults_sign_count():
    entry = _valid_credential_entry()
    entry["signCount"] = "9"  # Non-int values are intentionally normalized to 0.
    entry["properties"] = {"authenticator_attachment": "cross-platform"}

    records = advanced_parsing._parse_client_supplied_credentials([entry])

    assert len(records) == 1
    assert records[0]["attachment"] == "cross-platform"
    assert records[0]["signCount"] == 0


def test_optional_bool_flag_and_first_value_helpers():
    assert advanced_parsing._coerce_optional_bool(True) is True
    assert advanced_parsing._coerce_optional_bool(0) is False
    assert advanced_parsing._coerce_optional_bool('yes') is True
    assert advanced_parsing._coerce_optional_bool('No') is False
    assert advanced_parsing._coerce_optional_bool(float('nan')) is None
    assert advanced_parsing._coerce_optional_bool('maybe') is None
    mapping = {'resident': 'maybe', 'residentKey': 'true'}
    assert advanced_parsing._extract_flag_from_mapping(mapping, ('resident', 'residentKey')) is True
    assert advanced_parsing._extract_flag_from_mapping({}, ('resident',)) is None
