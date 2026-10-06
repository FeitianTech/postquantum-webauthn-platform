"""Tests for how the simple routes read the credentials the page sends back."""

from __future__ import annotations

import base64

from server.app.routes.simple import parsing
from server.app.routes.simple import parsing as simple_parsing
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import Authenticator, b64u
from tests.app.storage.credential_seed import sample_public_key_bytes


def _begin_registration(credentials):
    """What register begin excludes, and the copy of each credential authenticate keeps a digest of."""

    response = entry_app().test_client().post("/api/register/begin", json={"credentials": credentials})
    assert response.status_code == 200
    _attested, kept = parsing._parse_client_credentials(credentials)
    return response.get_json()["publicKey"]["excludeCredentials"], kept


def test_credentials_that_are_no_objects_are_passed_over():
    authenticator = Authenticator(credential_id=b"\x05" * 32)

    excluded, kept = _begin_registration(["not a credential", 42, authenticator.stored_credential_entry()])

    assert [entry["id"] for entry in excluded] == [b64u(authenticator.credential_id)]
    assert [entry["credentialId"] for entry in kept] == [b64u(authenticator.credential_id)]


def test_an_aaguid_given_in_hex_is_kept_in_the_credentials_copy():
    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    entry = Authenticator(aaguid=aaguid).stored_credential_entry()
    del entry["aaguid"]
    entry["aaguidHex"] = aaguid.hex(":")

    excluded, kept = _begin_registration([entry])

    assert len(excluded) == 1
    assert kept[0]["aaguid"] == b64u(aaguid)


def test_an_aaguid_given_as_plain_hex_is_read_as_hex_not_as_base64():
    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    entry = Authenticator(aaguid=aaguid).stored_credential_entry()
    del entry["aaguid"]
    entry["aaguidHex"] = aaguid.hex()

    excluded, kept = _begin_registration([entry])

    assert len(excluded) == 1
    assert kept[0]["aaguid"] == b64u(aaguid)


def _valid_credential_entry(**overrides):
    entry = {
        "email": "user@example.com",
        "userName": "user@example.com",
        "displayName": "User",
        "type": "simple",
        "aaguid": b64u(bytes.fromhex("00112233445566778899aabbccddeeff")),
        "credentialId": b64u(b"simple-credential-1"),
        "publicKey": b64u(sample_public_key_bytes()),
        "signCount": 7,
        "algorithm": -7,
    }
    entry.update(overrides)
    return entry


def test_parse_client_credentials_returns_empty_for_non_list_input():
    credentials, serialized = simple_parsing._parse_client_credentials({"not": "a-list"})

    assert credentials == []
    assert serialized == []


def test_parse_client_credentials_skips_entries_missing_required_fields():
    credentials, serialized = simple_parsing._parse_client_credentials(
        [
            {"credentialId": b64u(b"id-only"), "publicKey": b64u(sample_public_key_bytes())},
            {"aaguid": b64u(bytes(16)), "publicKey": b64u(sample_public_key_bytes())},
            {"aaguid": b64u(bytes(16)), "credentialId": b64u(b"id-only")},
        ]
    )

    assert credentials == []
    assert serialized == []


def test_parse_client_credentials_parses_aliases_and_serializes_metadata_fields():
    aaguid_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"alias-credential"
    public_key_bytes = sample_public_key_bytes()

    entry = {
        "email": "alias@example.com",
        "userName": "alias@example.com",
        "displayName": "Alias User",
        "type": "simple",
        "aaguidBase64": base64.b64encode(aaguid_bytes).decode("ascii"),
        "credentialID": b64u(credential_id),
        "publicKeyBase64Url": b64u(public_key_bytes),
        "signCount": 11,
        "publicKeyAlgorithm": -8,
    }

    credentials, serialized = simple_parsing._parse_client_credentials([entry])

    assert len(credentials) == 1
    assert len(serialized) == 1

    payload = serialized[0]
    assert payload["credentialId"] == b64u(credential_id)
    assert payload["aaguid"] == b64u(aaguid_bytes)
    assert payload["publicKey"] == b64u(public_key_bytes)
    assert payload["signCount"] == 11
    assert payload["algorithm"] == -8
    assert payload["publicKeyAlgorithm"] == -8
    assert payload["email"] == "alias@example.com"
    assert payload["userName"] == "alias@example.com"
    assert payload["displayName"] == "Alias User"
    assert payload["type"] == "simple"


def test_parse_client_credentials_skips_malformed_entries_and_keeps_valid_entries():
    malformed = _valid_credential_entry(credentialId="g$")
    valid = _valid_credential_entry(credentialId=b64u(b"good-credential"), signCount=4)

    credentials, serialized = simple_parsing._parse_client_credentials([malformed, valid])

    assert len(credentials) == 1
    assert len(serialized) == 1
    assert serialized[0]["credentialId"] == b64u(b"good-credential")
    assert serialized[0]["signCount"] == 4
