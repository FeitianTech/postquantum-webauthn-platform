"""Tests for what advanced register complete reads from its request."""
from __future__ import annotations

import pytest

from tests.app.entry_app import entry_app

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
