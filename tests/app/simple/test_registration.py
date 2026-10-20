"""Tests for the simple register routes."""

from __future__ import annotations

import time
from urllib.parse import urlencode

import pytest

from server.app.config import relying_party
from server.app.routes.simple import account
from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    Authenticator,
    b64u,
    registration_payload,
    unb64u,
)
from tests.app.storage.codec_examples import _stored_credential_entry

EMAIL = "user@example.com"


def test_a_begin_body_that_is_no_object_excludes_no_credential():
    response = entry_app().test_client().post(f"/api/register/begin?email={EMAIL}", json=["not", "an", "object"])

    assert response.status_code == 200
    assert response.get_json()["publicKey"]["excludeCredentials"] == []


def test_a_begin_excludes_the_credentials_it_is_sent_and_keeps_none_in_the_session():
    client = entry_app().test_client()
    authenticator = Authenticator()
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": [authenticator.stored_credential_entry()]})

    assert [entry["id"] for entry in begin.get_json()["publicKey"]["excludeCredentials"]] == [
        b64u(authenticator.credential_id)
    ]
    with client.session_transaction() as session:
        assert "simple_credentials" not in session


@pytest.mark.parametrize(
    ("query", "sentence"),
    [
        ({}, account.USERNAME_REQUIRED),
        ({"email": "  "}, account.USERNAME_REQUIRED),
        ({"email": "team/alice"}, account.USERNAME_RULES),
        ({"email": "a" * 65}, account.USERNAME_RULES),
    ],
)
def test_a_begin_for_a_username_that_cannot_be_one_issues_no_options(query, sentence):
    begin = entry_app().test_client().post(f"/api/register/begin?{urlencode(query)}", json={"credentials": []})

    assert begin.status_code == 400
    assert begin.get_json() == {"error": sentence}
    # Neither a ceremony in the session nor a namespace: no cookie at all.
    assert begin.headers.getlist("Set-Cookie") == []


def test_a_begin_keeps_only_what_the_checks_read_and_none_of_its_exclude_list():
    client = entry_app().test_client()
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": [Authenticator().stored_credential_entry()]})

    assert len(begin.get_json()["publicKey"]["excludeCredentials"]) == 1
    with client.session_transaction() as session:
        assert sorted(session["simple_register_public_key"]) == ["authenticatorSelection", "challenge", "pubKeyCredParams"]


def test_a_begin_keeps_the_algorithms_it_offers_for_complete():
    client = entry_app().test_client()
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": []})

    offered = [param["alg"] for param in begin.get_json()["publicKey"]["pubKeyCredParams"]]
    with client.session_transaction() as session:
        kept = [param["alg"] for param in session["simple_register_public_key"]["pubKeyCredParams"]]
    assert kept == offered
    assert -36 not in kept and -65535 not in kept


def test_a_credential_whose_algorithm_was_not_offered_is_refused(credential_store, tmp_path):
    client = entry_app().test_client()
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    # ES512: this server verifies it, but the begin did not offer it.
    complete = client.post(
        f"/api/register/complete?email={EMAIL}",
        json=registration_payload(Authenticator(key_type="es512"), challenge=challenge),
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 400
    assert complete.get_json() == {
        "error": "Registration verification failed.",
        "verified": False,
        "attestationErrors": ["algorithm_not_allowed"],
    }
    assert list((tmp_path / "credentials").rglob("*.json")) == []


def test_a_complete_body_that_is_no_object_finds_no_registration_state():
    response = entry_app().test_client().post(
        f"/api/register/complete?email={EMAIL}", json=["not", "a", "registration"]
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Registration state not found or has expired. Please restart the registration process."
    }


@pytest.mark.parametrize("member", [None, "attestation", ["attestation"]])
def test_a_complete_whose_response_is_no_object_finds_no_registration_state(member):
    response = entry_app().test_client().post(f"/api/register/complete?email={EMAIL}", json={"response": member})

    assert response.status_code == 400
    assert response.get_json()["error"].startswith("Registration state not found")


def test_a_registration_challenge_past_its_lifetime_is_refused_as_expired():
    client = entry_app().test_client()
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    with client.session_transaction() as session:
        session["simple_register_state"] = {**session["simple_register_state"], "issued_at": time.time() - 24 * 3600}

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


def _register_complete_payload(*, state=None):
    payload = {
        "rawId": b64u(b"simple-register-failure"),
        "response": {
            "attestationObject": b64u(b"attestation"),
            "clientDataJSON": b64u(b"client-data"),
        },
    }
    if state is not None:
        payload["__session_state"] = state
    return payload


def test_simple_register_complete_returns_400_and_cleans_state_when_verification_fails(monkeypatch):
    class _FailingServer:
        def register_complete(self, *_args, **_kwargs):
            raise ValueError("register verification failed")

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda: "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FailingServer())
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["simple_register_state"] = {"challenge": "session-state", "issued_at": time.time()}
            session_state["register_rp_id"] = "example.com"
            session_state["simple_register_public_key"] = {"challenge": "saved"}

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json=_register_complete_payload(),
        )

        assert response.status_code == 400
        assert response.get_json() == {"error": "register verification failed"}

        with client.session_transaction() as session_state:
            assert "simple_register_state" not in session_state
            assert "register_rp_id" not in session_state
            assert "simple_register_public_key" not in session_state


def test_simple_register_complete_rejects_request_state_fallback_before_verification(monkeypatch):
    """The request-supplied state must be discarded before any verification."""

    captured = {}

    class _FailingServer:
        def register_complete(self, state, *_args, **_kwargs):
            captured["state"] = state
            raise ValueError("fallback verification failed")

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda: "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FailingServer())
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )

    fallback_state = {"challenge": "request-fallback-state"}

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["register_rp_id"] = "example.com"

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json=_register_complete_payload(state=fallback_state),
        )

        assert response.status_code == 400
        # Rejected for a missing session state, NOT by the verifier: the
        # client-supplied challenge never reaches register_complete at all.
        assert "state" in response.get_json()["error"].lower()
        assert "state" not in captured

        with client.session_transaction() as session_state:
            assert "register_rp_id" not in session_state


def test_simple_register_begin_accepts_existing_credentials_alias(monkeypatch):
    captured = {}

    class _FakeServer:
        def register_begin(self, _user, credentials, **_kwargs):
            captured["credential_count"] = len(credentials)
            return {
                "publicKey": {
                    "challenge": "AQID",
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                }
            }, {"challenge": "simple-register-state"}

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda: "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())

    with entry_app().test_client() as client:
        response = client.post(
            "/api/register/begin?email=user@example.com",
            json={"existingCredentials": [_stored_credential_entry(b"simple-register-alias")]},
        )

        assert response.status_code == 200
        payload = response.get_json()
        # The ceremony state stays server-side and is never echoed back.
        assert "__session_state" not in payload
        assert captured["credential_count"] == 1

        with client.session_transaction() as session_state:
            assert session_state["simple_register_state"]["challenge"] == "simple-register-state"
            assert isinstance(session_state["simple_register_state"]["issued_at"], float)

        with client.session_transaction() as session_state:
            assert "simple_credentials" not in session_state
