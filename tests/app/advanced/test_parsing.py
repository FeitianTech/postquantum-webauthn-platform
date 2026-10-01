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
