"""A credential name the store refuses is a 400, logged in one line, never a 500.

The store rejects a traversal name (``../x``) before touching a path; that
used to surface as HTTP 500 with a full stack trace in the log. Every route
that hands storage a caller's name now answers 400 without a traceback.
"""
from __future__ import annotations

import logging

import pytest

from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    advanced_public_key_options,
    assertion_payload,
    registration_payload,
    unb64u,
)

TRAVERSAL = "../x"


@pytest.fixture
def store(monkeypatch, tmp_path, storage_module, device_logs_module):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setattr(storage_module, "_LOCAL_CREDENTIAL_BASE", str(tmp_path / "credentials"))
    monkeypatch.setattr(storage_module, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(tmp_path / "legacy"))
    monkeypatch.setattr(storage_module, "basepath", str(tmp_path / "flat"))
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)
    return tmp_path


def _assert_refused_without_traceback(response, caplog):
    assert response.status_code == 400, response.get_json()
    assert response.get_json()["error"].startswith("Invalid credential name: ")
    assert [record for record in caplog.records if record.exc_info] == []
    assert any("Refused a storage name" in record.getMessage() for record in caplog.records)


def test_download_refuses_a_traversal_name(client, caplog, store):
    with caplog.at_level(logging.WARNING):
        response = client.get(f"/api/downloadcred?email={TRAVERSAL}")

    _assert_refused_without_traceback(response, caplog)


def test_delete_refuses_a_traversal_name(client, caplog, store):
    with caplog.at_level(logging.WARNING):
        response = client.post("/api/deletepub", json={"email": TRAVERSAL})

    _assert_refused_without_traceback(response, caplog)


def test_simple_registration_refuses_a_traversal_name(client, caplog, store):
    begin = client.post(f"/api/register/begin?email={TRAVERSAL}", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    with caplog.at_level(logging.WARNING):
        response = client.post(
            f"/api/register/complete?email={TRAVERSAL}",
            json=registration_payload(Authenticator(), challenge=challenge),
            headers={"Origin": ORIGIN},
        )

    _assert_refused_without_traceback(response, caplog)
    assert not (store / "x_credential_data.json").exists()


def test_simple_authentication_refuses_a_traversal_name(client, caplog, store):
    authenticator = Authenticator()
    begin = client.post("/api/register/begin?email=user@example.com", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    registered = client.post(
        "/api/register/complete?email=user@example.com",
        json=registration_payload(authenticator, challenge=challenge),
        headers={"Origin": ORIGIN},
    )
    assert registered.status_code == 200, registered.get_json()

    begin = client.post(
        f"/api/authenticate/begin?email={TRAVERSAL}", json={"credentials": [authenticator.stored_credential_entry()]}
    )
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    with caplog.at_level(logging.WARNING):
        response = client.post(
            f"/api/authenticate/complete?email={TRAVERSAL}",
            json=assertion_payload(authenticator, challenge=challenge, counter=1),
            headers={"Origin": ORIGIN},
        )

    _assert_refused_without_traceback(response, caplog)


@pytest.mark.parametrize("username", [TRAVERSAL, "team/alice"])
def test_the_advanced_flow_does_not_hand_its_user_name_to_the_store(client, caplog, store, advanced_storage, username):
    # The advanced flow stores nothing under the user name, so any WebAuthn
    # user.name registers; it used to be read (and discarded) through the store.
    authenticator = Authenticator()
    begin = client.post(
        "/api/advanced/register/begin",
        json={"publicKey": advanced_public_key_options(challenge=b"\x31" * 32, username=username)},
    )
    body = begin.get_json()
    challenge = unb64u(body["publicKey"]["challenge"])

    with caplog.at_level(logging.WARNING):
        response = client.post(
            "/api/advanced/register/complete",
            json={
                "publicKey": advanced_public_key_options(challenge=challenge, username=username),
                "__credential_response": registration_payload(authenticator, challenge=challenge),
                "__session_state": body["__session_state"],
            },
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 200, response.get_json()
    assert [record for record in caplog.records if record.exc_info] == []


def test_the_refusal_is_still_a_value_error(storage_module):
    from server.app.storage.common import InvalidStorageIdentifier

    with pytest.raises(InvalidStorageIdentifier) as refused:
        storage_module.readkey(TRAVERSAL, session_id="session-a")

    assert isinstance(refused.value, ValueError)
