"""Tests for how the simple routes read the credentials the page sends back."""
from __future__ import annotations

from server.app.routes.simple import parsing
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import Authenticator, b64u


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
