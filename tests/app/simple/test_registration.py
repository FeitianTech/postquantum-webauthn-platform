"""Tests for the simple register routes."""
from __future__ import annotations

import time

from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    Authenticator,
    registration_payload,
    unb64u,
)

EMAIL = "user@example.com"


def test_a_begin_body_that_is_no_object_excludes_no_credential():
    response = entry_app().test_client().post("/api/register/begin", json=["not", "an", "object"])

    assert response.status_code == 200
    assert response.get_json()["publicKey"]["excludeCredentials"] == []


def test_a_begin_without_credentials_forgets_the_ones_an_earlier_begin_kept():
    client = entry_app().test_client()
    client.post("/api/register/begin", json={"credentials": [Authenticator().stored_credential_entry()]})
    with client.session_transaction() as session:
        assert len(session["simple_credentials"]) == 1

    client.post("/api/register/begin", json={"credentials": []})

    with client.session_transaction() as session:
        assert "simple_credentials" not in session


def test_a_complete_body_that_is_no_object_finds_no_registration_state():
    response = entry_app().test_client().post(
        f"/api/register/complete?email={EMAIL}", json=["not", "a", "registration"]
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Registration state not found or has expired. Please restart the registration process."
    }


def test_a_registration_challenge_past_its_lifetime_is_refused_as_expired():
    client = entry_app().test_client()
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    with client.session_transaction() as session:
        session["state"] = {**session["state"], "issued_at": time.time() - 24 * 3600}

    response = client.post(
        f"/api/register/complete?email={EMAIL}",
        json=registration_payload(Authenticator(), challenge=challenge),
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Registration challenge has expired. Please restart the registration process."
    }
    with client.session_transaction() as session:
        assert "register_rp_id" not in session
        assert "simple_register_public_key" not in session
