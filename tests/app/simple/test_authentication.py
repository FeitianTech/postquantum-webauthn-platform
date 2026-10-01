"""Tests for the simple authenticate routes and their signature-counter check.

The ceremonies are genuinely signed (``ceremony_helpers``) and the credential
store is the real one, in this test's directory.
"""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from fido2.webauthn import AuthenticatorData

from server.app.routes.simple import authentication as simple_authentication
from server.app.storage import credentials as storage_credentials
from server.app.storage import github_mirror
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    RP_ID,
    Authenticator,
    assertion_payload,
    b64u,
    registration_payload,
    unb64u,
)

EMAIL = "user@example.com"


@pytest.fixture
def credential_store(monkeypatch, tmp_path):
    """The real credential store, in this test's directory; no registration is mirrored."""

    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(tmp_path / "credentials"))
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda _event: None)


def _register(client, authenticator, *, counter):
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        f"/api/register/complete?email={EMAIL}",
        json=registration_payload(authenticator, challenge=challenge, counter=counter),
        headers={"Origin": ORIGIN},
    )
    assert complete.status_code == 200, complete.get_json()


def _authenticate(client, authenticator, *, counter, query=f"?email={EMAIL}", client_sign_count=None):
    entry = authenticator.stored_credential_entry()
    if client_sign_count is not None:
        entry["signCount"] = client_sign_count
    begin = client.post(f"/api/authenticate/begin{query}", json={"credentials": [entry]})
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    return client.post(
        f"/api/authenticate/complete{query}",
        json=assertion_payload(authenticator, challenge=challenge, counter=counter),
        headers={"Origin": ORIGIN},
    )


def test_a_begin_body_that_is_no_object_offers_no_credential():
    response = entry_app().test_client().post("/api/authenticate/begin", json=["not", "an", "object"])

    assert response.status_code == 404


def test_an_assertion_body_that_is_no_object_fails_without_naming_a_credential(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    begin = client.post(
        f"/api/authenticate/begin?email={EMAIL}",
        json={"credentials": [authenticator.stored_credential_entry()]},
    )
    assert begin.status_code == 200

    response = client.post(f"/api/authenticate/complete?email={EMAIL}", json=["not", "an", "assertion"])

    assert response.status_code == 400
    assert response.get_json()["error"]
    assert "failedCredentialId" not in response.get_json()


def test_without_an_email_the_counter_is_checked_against_the_browsers_copy(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()

    lower = _authenticate(client, authenticator, counter=3, query="", client_sign_count=5)
    higher = _authenticate(client, authenticator, counter=6, query="", client_sign_count=5)

    assert lower.status_code == 400
    assert lower.get_json()["signCountStatus"] == "regressed"
    assert "stored 5, received 3" in lower.get_json()["error"]
    assert higher.status_code == 200
    assert higher.get_json()["signCount"] == 6


def test_a_credential_the_server_holds_no_record_of_is_checked_against_the_browsers_copy(credential_store):
    registered = Authenticator(credential_id=b"\x01" * 32)
    unregistered = Authenticator(credential_id=b"\x02" * 32)
    client = entry_app().test_client()
    _register(client, registered, counter=10)

    response = _authenticate(client, unregistered, counter=2, client_sign_count=4)

    assert response.status_code == 400
    assert "stored 4, received 2" in response.get_json()["error"]
    assert response.get_json()["failedCredentialId"] == b64u(unregistered.credential_id)


def test_a_counter_that_cannot_be_saved_fails_the_authentication(credential_store, monkeypatch, caplog):
    authenticator = Authenticator()
    client = entry_app().test_client()
    _register(client, authenticator, counter=1)

    def _refuse(*_args, **_kwargs):
        raise OSError("the disk is full")

    monkeypatch.setattr(storage_credentials, "save_if_unchanged", _refuse)
    response = _authenticate(client, authenticator, counter=5)

    assert response.status_code == 500
    assert response.get_json() == {"error": "Unable to persist the signature counter."}
    assert "Failed to persist signature counter for " + b64u(authenticator.credential_id) in caplog.text


def test_a_record_names_its_credential_only_by_its_credential_datas_bytes():
    registered = AuthenticatorData(Authenticator(credential_id=b"\x07" * 16).authenticator_data())

    assert simple_authentication.record_credential_id({"credential_data": registered.credential_data}) == b"\x07" * 16
    assert simple_authentication.record_credential_id(["not", "a", "record"]) is None
    assert simple_authentication.record_credential_id({}) is None


def test_a_record_without_a_counter_of_its_own_has_its_authenticator_datas():
    auth_data = AuthenticatorData.create(hashlib.sha256(RP_ID.encode()).digest(), 0x01, 7)

    assert simple_authentication.record_sign_count({"sign_count": 9, "auth_data": auth_data}) == 9
    assert simple_authentication.record_sign_count({"sign_count": True, "auth_data": auth_data}) == 7
    assert simple_authentication.record_sign_count({}) is None


def test_the_browsers_counter_is_read_only_from_an_entry_naming_the_credential():
    entries = [
        "not an entry",
        {"signCount": 9},
        {"credentialId": 12.5, "signCount": 9},
        {"credentialId": b64u(b"another credential"), "signCount": 9},
    ]

    assert simple_authentication.client_supplied_sign_count(entries, b"this credential") is None
    assert simple_authentication.client_supplied_sign_count(
        [*entries, {"credentialId": b64u(b"this credential"), "signCount": 4}], b"this credential"
    ) == 4


def test_a_matched_credential_without_readable_bytes_has_no_id():
    assert simple_authentication._matched_credential_id(SimpleNamespace(credential_id=object())) == b""
