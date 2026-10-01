"""Tests for what advanced register complete reads from its request."""
from __future__ import annotations

from tests.app.entry_app import entry_app

from .registration_ceremony import register


def _complete(body):
    return entry_app().test_client().post("/api/advanced/register/complete", json=body)


def test_a_request_without_a_credential_response_is_refused():
    response = _complete({"publicKey": {"user": {"name": "user@example.com"}}})

    assert response.status_code == 400
    assert response.get_json() == {"error": "Credential response is required"}


def test_a_request_without_public_key_options_is_refused():
    response = _complete({"__credential_response": {"response": {}}})

    assert response.status_code == 400
    assert response.get_json()["error"] == "Invalid request: Missing publicKey in JSON editor content"


def test_a_request_without_a_user_name_is_refused():
    response = _complete(
        {
            "publicKey": {"challenge": "AQID", "user": {"name": "", "displayName": "User"}},
            "__credential_response": {"response": {}},
        }
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Username is required in user.name"


def test_an_authenticator_selection_that_is_no_object_asks_for_no_resident_key(advanced_stores):
    response = register(entry_app().test_client(), public_key_changes={"authenticatorSelection": "not an object"})

    assert response.status_code == 200, response.get_json()
    properties = response.get_json()["storedCredential"]["properties"]
    assert properties["residentKeyRequested"] is None
    assert properties["residentKeyRequired"] is False
