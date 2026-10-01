"""Tests for the options advanced authenticate begin gives fido2 and the browser."""
from __future__ import annotations

import pytest

from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    Authenticator,
    advanced_public_key_options,
)

from .assertion_ceremony import begin


def _options(response):
    assert response.status_code == 200, response.get_json()
    return response.get_json()["publicKey"]


def test_authentication_is_for_the_rp_of_the_last_registration_begin():
    client = entry_app().test_client()
    registration_options = advanced_public_key_options(challenge=b"\x01" * 32)
    client.post("/api/advanced/register/begin", json={"publicKey": registration_options})

    options = _options(begin(client, [Authenticator().stored_credential_entry()]))

    assert options["rpId"] == registration_options["rp"]["id"]
    with client.session_transaction() as session:
        assert session["advanced_auth_rp"] == registration_options["rp"]


@pytest.mark.parametrize(
    ("requested", "asked"),
    [("required", "required"), ("discouraged", "discouraged"), ("anything else", "preferred")],
)
def test_the_requested_user_verification_is_asked_for(requested, asked):
    options = _options(begin(entry_app().test_client(), [Authenticator().stored_credential_entry()], userVerification=requested))

    assert options["userVerification"] == asked


@pytest.mark.parametrize(
    "extensions",
    [
        {"largeBlob": {"read": True}, "prf": {"salt": "abc"}, "txAuthSimple": "hello"},
        {"largeBlob": {"support": "preferred"}},
        {"largeBlob": "required"},
    ],
)
def test_extensions_without_bytes_to_read_are_passed_on_as_they_are(extensions):
    options = _options(begin(entry_app().test_client(), [Authenticator().stored_credential_entry()], extensions=extensions))

    assert options["extensions"] == extensions


def test_prf_inputs_for_each_credential_are_given_to_the_browser_with_the_general_ones():
    extensions = {
        "prf": {
            "eval": {"first": {"$hex": "0101"}},
            "evalByCredential": {"BAQE": {"first": "0202", "second": {"$base64url": "AwM"}}},
        }
    }

    options = _options(begin(entry_app().test_client(), [Authenticator().stored_credential_entry()], extensions=extensions))

    assert options["extensions"] == {
        "prf": {"eval": {"first": "AQE"}, "evalByCredential": {"BAQE": {"first": "AgI", "second": "AwM"}}},
    }


def test_prf_with_no_input_to_read_asks_for_no_prf():
    options = _options(
        begin(entry_app().test_client(), [Authenticator().stored_credential_entry()], extensions={"prf": {"eval": {}}})
    )

    assert "extensions" not in options or "prf" not in options["extensions"]
