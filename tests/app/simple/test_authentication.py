"""Tests for the simple authenticate routes and their signature-counter check.

The ceremonies are genuinely signed (``ceremony_helpers``) and the credential
store is the real one, in this test's directory.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from server.app.config import relying_party
from server.app.routes.simple import authentication as simple_authentication
from server.app.storage import credentials as storage_credentials
from tests.app.characterization import material
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    Authenticator,
    assertion_payload,
    authenticate_simple,
    b64u,
    register_simple,
    simple_complete_body,
    unb64u,
)
from tests.app.storage.codec_examples import _stored_credential_entry

EMAIL = "user@example.com"


# Werkzeug's limit for a Set-Cookie header, just under what browsers keep (4,096 bytes).
COOKIE_LIMIT = 4093


def _cookies_fit(response) -> bool:
    return all(len(header) <= COOKIE_LIMIT for header in response.headers.getlist("Set-Cookie"))


@pytest.mark.parametrize(("key_type", "count"), [("ML-DSA-65", 2), ("ML-DSA-87", 3)])
def test_several_ml_dsa_passkeys_authenticate_with_every_cookie_a_browser_keeps(credential_store, key_type, count):
    client = entry_app().test_client()
    authenticators = [material.Authenticator(f"{key_type}-passkey-{index}", key_type=key_type) for index in range(count)]
    for authenticator in authenticators:
        register_simple(client, authenticator)
    credentials = [authenticator.stored_credential_entry() for authenticator in authenticators]

    begin = client.post(f"/api/authenticate/begin?email={EMAIL}", json={"credentials": credentials})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        f"/api/authenticate/complete?email={EMAIL}",
        json=simple_complete_body(assertion_payload(authenticators[-1], challenge=challenge, counter=1), credentials),
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
    assert _cookies_fit(begin)
    assert _cookies_fit(complete)


def test_a_complete_sent_other_credentials_than_its_begin_is_refused(credential_store):
    client = entry_app().test_client()
    first, second = Authenticator(credential_id=b"\x01" * 32), Authenticator(credential_id=b"\x02" * 32)
    for authenticator in (first, second):
        register_simple(client, authenticator)
    begun_with = [first.stored_credential_entry(), second.stored_credential_entry()]

    begin = client.post(f"/api/authenticate/begin?email={EMAIL}", json={"credentials": begun_with})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        f"/api/authenticate/complete?email={EMAIL}",
        json=simple_complete_body(assertion_payload(first, challenge=challenge, counter=1), begun_with[:1]),
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 400
    assert "not the ones it began with" in complete.get_json()["error"]


def test_a_complete_for_another_email_than_its_begin_is_refused(credential_store):
    client = entry_app().test_client()
    authenticator = Authenticator()
    register_simple(client, authenticator)
    register_simple(client, authenticator, email="other@example.com")
    stored = [authenticator.stored_credential_entry()]

    begin = client.post(f"/api/authenticate/begin?email={EMAIL}", json={"credentials": stored})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        "/api/authenticate/complete?email=other@example.com",
        json=simple_complete_body(assertion_payload(authenticator, challenge=challenge, counter=1), stored),
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 400
    assert complete.get_json()["error"].startswith("This authentication began for another email.")


def test_a_begin_body_that_is_no_object_offers_no_credential():
    response = entry_app().test_client().post("/api/authenticate/begin", json=["not", "an", "object"])

    assert response.status_code == 404


def test_an_assertion_body_that_is_no_object_fails_without_naming_a_credential(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    stored = [authenticator.stored_credential_entry()]
    begin = client.post(f"/api/authenticate/begin?email={EMAIL}", json={"credentials": stored})
    assert begin.status_code == 200

    response = client.post(
        f"/api/authenticate/complete?email={EMAIL}", json=simple_complete_body(["not", "an", "assertion"], stored)
    )

    assert response.status_code == 400
    assert response.get_json()["error"]
    assert "failedCredentialId" not in response.get_json()


def test_without_an_email_the_counter_is_checked_against_the_browsers_copy(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()

    lower = authenticate_simple(client, authenticator, counter=3, email=None, client_sign_count=5)
    higher = authenticate_simple(client, authenticator, counter=6, email=None, client_sign_count=5)

    assert lower.status_code == 400
    assert lower.get_json()["signCountStatus"] == "regressed"
    assert "stored 5, received 3" in lower.get_json()["error"]
    assert higher.status_code == 200
    assert higher.get_json()["signCount"] == 6


def test_a_credential_the_server_holds_no_record_of_is_checked_against_the_browsers_copy(credential_store):
    registered = Authenticator(credential_id=b"\x01" * 32)
    unregistered = Authenticator(credential_id=b"\x02" * 32)
    client = entry_app().test_client()
    register_simple(client, registered, counter=10)

    response = authenticate_simple(client, unregistered, counter=2, client_sign_count=4)

    assert response.status_code == 400
    assert "stored 4, received 2" in response.get_json()["error"]
    assert response.get_json()["failedCredentialId"] == b64u(unregistered.credential_id)


def test_a_visitor_without_a_namespace_is_checked_against_the_browsers_copy_and_given_none(credential_store):
    # Registered from another browser, or this one's cookies cleared: nothing is stored for it here.
    authenticator = Authenticator()
    register_simple(entry_app().test_client(), authenticator, counter=10)
    client = entry_app().test_client()

    lower = authenticate_simple(client, authenticator, counter=3, client_sign_count=5)
    higher = authenticate_simple(client, authenticator, counter=6, client_sign_count=5)

    assert "stored 5, received 3" in lower.get_json()["error"]
    assert higher.status_code == 200, higher.get_json()
    assert client.get_cookie("fido.mds.session") is None
    with client.session_transaction() as session:
        assert "fido.mds.session" not in session


def test_a_counter_that_cannot_be_saved_fails_the_authentication(credential_store, monkeypatch, caplog):
    authenticator = Authenticator()
    client = entry_app().test_client()
    register_simple(client, authenticator, counter=1)

    def _refuse(*_args, **_kwargs):
        raise OSError("the disk is full")

    monkeypatch.setattr(storage_credentials, "save_if_unchanged", _refuse)
    response = authenticate_simple(client, authenticator, counter=5)

    assert response.status_code == 500
    assert response.get_json() == {"error": "Unable to persist the signature counter."}
    assert "Failed to persist signature counter for " + b64u(authenticator.credential_id) in caplog.text


def test_a_matched_credential_without_readable_bytes_has_no_id():
    assert simple_authentication._matched_credential_id(SimpleNamespace(credential_id=object())) == b""


def test_simple_authenticate_begin_accepts_stored_credentials_alias(monkeypatch):
    captured = {}

    class _FakeServer:
        def authenticate_begin(self, credentials, **_kwargs):
            captured["credential_count"] = len(credentials)
            return {"publicKey": {"challenge": "AQID"}}, {"challenge": "simple-auth-state"}

    monkeypatch.setattr(relying_party, "determine_rp_id", lambda: "example.com")
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())

    with entry_app().test_client() as client:
        response = client.post(
            "/api/authenticate/begin?email=user@example.com",
            json={"storedCredentials": [_stored_credential_entry(b"simple-auth-alias")]},
        )

        assert response.status_code == 200
        payload = response.get_json()
        # The ceremony state stays server-side and is never echoed back.
        assert "__session_state" not in payload
        assert captured["credential_count"] == 1

        with client.session_transaction() as session_state:
            assert session_state["state"]["challenge"] == "simple-auth-state"
            assert isinstance(session_state["state"]["issued_at"], float)
            # The credentials' digest, never their public keys: complete is sent them again.
            assert "simple_credentials" not in session_state
            assert isinstance(session_state["simple_credentials_digest"], str)
