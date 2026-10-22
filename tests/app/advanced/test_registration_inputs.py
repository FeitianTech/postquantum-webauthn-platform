"""Tests for what advanced register complete reads from its request."""
from __future__ import annotations

import pytest

from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    Authenticator,
    advanced_public_key_options,
    registration_payload,
    unb64u,
)

from .registration_ceremony import register


def _complete(body):
    return entry_app().test_client().post("/api/advanced/register/complete", json=body)


@pytest.mark.parametrize("body", [["publicKey"], "publicKey"])
def test_a_body_that_is_no_object_has_no_credential_response(body):
    response = _complete(body)

    assert response.status_code == 400
    assert response.get_json() == {"error": "Credential response is required"}


def test_a_member_of_the_wrong_type_is_refused_before_the_registration_is_verified():
    response = _complete(
        {
            "publicKey": {"challenge": "AQID", "user": {"name": "user@example.com"}, "extensions": None},
            "__credential_response": {"response": {}},
        }
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "extensions must be an object."}


@pytest.mark.parametrize("inner", ["attestation", ["attestation"]])
def test_a_response_member_that_is_no_object_is_read_as_none(inner):
    response = _complete(
        {"publicKey": {"challenge": "AQID", "user": {"name": "user@example.com"}}, "__credential_response": {"response": inner}}
    )

    assert response.status_code == 400
    assert response.get_json()["error"].startswith("Registration state not found")


def test_an_authenticator_selection_that_is_no_object_asks_for_no_resident_key(advanced_stores):
    response = register(entry_app().test_client(), public_key_changes={"authenticatorSelection": "not an object"})

    assert response.status_code == 200, response.get_json()
    properties = response.get_json()["storedCredential"]["properties"]
    assert properties["residentKeyRequested"] is None
    assert properties["residentKeyRequired"] is False


def test_a_state_whose_relying_party_is_gone_from_the_session_is_not_found():
    client = entry_app().test_client()
    begin = client.post("/api/advanced/register/begin", json={"publicKey": advanced_public_key_options(challenge=b"\x73" * 32)})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    with client.session_transaction() as session_state:
        del session_state["advanced_rp"]

    response = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(challenge=challenge),
            "__credential_response": registration_payload(Authenticator(), challenge=challenge),
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Registration state not found or has expired. Please restart the registration process.",
        "challengeSource": "server-session",
        "challengeStatus": "fresh",
    }
