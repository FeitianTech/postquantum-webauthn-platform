"""Tests for how the advanced routes read the credentials the page sends back."""
from __future__ import annotations

from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import Authenticator

from .assertion_ceremony import begin


def test_a_resident_flag_given_as_null_is_read_from_the_next_field_that_gives_one():
    said_by_cred_props = {
        **Authenticator(credential_id=b"\x01" * 32).stored_credential_entry(),
        "resident": None,
        "clientExtensionOutputs": {"credProps": {"rk": True}},
    }
    said_nowhere = {**Authenticator(credential_id=b"\x02" * 32).stored_credential_entry(), "resident": None}
    client = entry_app().test_client()

    response = begin(client, [said_by_cred_props, said_nowhere])

    assert response.status_code == 200, response.get_json()
    with client.session_transaction() as session:
        assert session["advanced_auth_credentials_meta"] == {"count": 2, "resident_count": 1}


def test_an_aaguid_given_as_plain_hex_is_read_as_hex_not_as_base64():
    authenticator = Authenticator(credential_id=b"\x03" * 32, aaguid=bytes.fromhex("00112233445566778899aabbccddeeff"))
    entry = authenticator.stored_credential_entry()
    entry["aaguidHex"] = authenticator.aaguid.hex()
    del entry["aaguid"]

    client = entry_app().test_client()

    response = begin(client, [entry])

    assert response.status_code == 200, response.get_json()
    with client.session_transaction() as session:
        assert session["advanced_auth_credentials_meta"]["count"] == 1
