"""A credential name the store refuses is a 400, logged in one line, never a 500.

The store rejects a traversal name (``../x``) before touching a path; that
used to surface as HTTP 500 with a full stack trace in the log. Every route
that hands storage a caller's name now answers 400 without a traceback, and the
Simple tab's begins refuse such a name before any options are issued
(``routes/simple/account.py``), so it never reaches the store.
"""
from __future__ import annotations

import logging

import pytest

from server.app.routes.simple import account
from server.app.storage import credentials as storage_credentials
from server.app.storage import github_mirror
from server.app.storage.common import InvalidStorageIdentifier

from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    advanced_public_key_options,
    registration_payload,
    unb64u,
)

TRAVERSAL = "../x"


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(tmp_path / "credentials"))
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda _event: None)
    return tmp_path


def _assert_refused_at_begin(response, caplog):
    assert response.status_code == 400, response.get_json()
    assert response.get_json() == {"error": account.USERNAME_RULES}
    assert [record for record in caplog.records if record.exc_info] == []


def test_the_store_refuses_a_traversal_name_before_touching_a_path(store):
    with pytest.raises(InvalidStorageIdentifier):
        storage_credentials.readkey(TRAVERSAL, session_id="session-name-errors")

    assert sorted(path.name for path in store.iterdir()) == []


def test_simple_registration_refuses_a_traversal_name_at_its_begin(client, caplog, store):
    with caplog.at_level(logging.WARNING):
        begin = client.post(f"/api/register/begin?email={TRAVERSAL}", json={"credentials": []})

    _assert_refused_at_begin(begin, caplog)
    assert sorted(path.name for path in store.iterdir()) == []


def test_simple_authentication_refuses_a_traversal_name_at_its_begin(client, caplog, store):
    with caplog.at_level(logging.WARNING):
        begin = client.post(
            f"/api/authenticate/begin?email={TRAVERSAL}", json={"credentials": [Authenticator().stored_credential_entry()]}
        )

    _assert_refused_at_begin(begin, caplog)
    assert sorted(path.name for path in store.iterdir()) == []


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
            },
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 200, response.get_json()
    assert [record for record in caplog.records if record.exc_info] == []
