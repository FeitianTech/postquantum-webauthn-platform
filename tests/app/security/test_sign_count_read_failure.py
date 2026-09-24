"""A stored signature counter that cannot be read rejects the authentication.

The simple flow compares an assertion's counter with the larger of the server's
stored counter and the browser's copy. When reading the server's records failed,
the check used to go on with the browser's copy alone -- which the browser can
omit or lower -- so a cloned authenticator passed whenever the store was down.
A failed read now answers 503 and saves nothing. A read that works but finds no
record for the credential still falls back to the browser's copy, as before.

Genuine signatures and the real credential store in a temporary directory; only
the read that is meant to fail is patched.
"""
from __future__ import annotations

import logging

import pytest

from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    assertion_payload,
    registration_payload,
    unb64u,
)

EMAIL = "user@example.com"
_CEREMONY_KEYS = {"state", "simple_credentials", "authenticate_rp_id", "simple_credentials_email"}


@pytest.fixture
def store(monkeypatch, tmp_path, storage_module, device_logs_module):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setattr(storage_module, "_LOCAL_CREDENTIAL_BASE", str(tmp_path / "credentials"))
    monkeypatch.setattr(storage_module, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(tmp_path / "legacy"))
    monkeypatch.setattr(storage_module, "basepath", str(tmp_path / "flat"))
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)
    return storage_module


@pytest.fixture
def saves(monkeypatch, store):
    calls = []
    original = store.save_if_unchanged

    def _recording_save(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "save_if_unchanged", _recording_save)
    return calls


def _register(client, authenticator, counter):
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        f"/api/register/complete?email={EMAIL}",
        json=registration_payload(authenticator, challenge=challenge, counter=counter),
        headers={"Origin": ORIGIN},
    )
    assert complete.status_code == 200, complete.get_json()


def _authenticate(client, authenticator, *, counter, client_sign_count=None):
    entry = authenticator.stored_credential_entry()
    if client_sign_count is not None:
        entry["signCount"] = client_sign_count
    begin = client.post(f"/api/authenticate/begin?email={EMAIL}", json={"credentials": [entry]})
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    return client.post(
        f"/api/authenticate/complete?email={EMAIL}",
        json=assertion_payload(authenticator, challenge=challenge, counter=counter),
        headers={"Origin": ORIGIN},
    )


def _session(client):
    with client.session_transaction() as state:
        return dict(state)


@pytest.mark.parametrize("client_sign_count", [None, 3], ids=["no-client-count", "client-count"])
def test_a_failed_read_of_the_stored_counter_rejects_the_authentication(
    app, monkeypatch, caplog, store, saves, client_sign_count
):
    authenticator = Authenticator()
    client = app.test_client()
    # Stored 10: an assertion carrying 5 is a regression the store would catch.
    _register(client, authenticator, counter=10)
    saves.clear()

    def _unreachable(*_args, **_kwargs):
        raise OSError("bucket unreachable at /secret/path")

    monkeypatch.setattr(store, "read_for_update", _unreachable)
    entry = authenticator.stored_credential_entry()
    if client_sign_count is not None:
        entry["signCount"] = client_sign_count
    begin = client.post(f"/api/authenticate/begin?email={EMAIL}", json={"credentials": [entry]})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    before = _session(client)

    with caplog.at_level(logging.INFO, logger="server.app"):
        response = client.post(
            f"/api/authenticate/complete?email={EMAIL}",
            json=assertion_payload(authenticator, challenge=challenge, counter=5),
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 503, response.get_json()
    body = response.get_json()
    assert list(body) == ["error"]
    assert "could not be read" in body["error"]
    assert "Traceback" not in response.get_data(as_text=True)
    assert "/secret/path" not in response.get_data(as_text=True)
    assert saves == []
    after = _session(client)
    # The ceremony's own keys are consumed, as on every rejection; nothing else moves.
    assert {k: v for k, v in before.items() if k not in _CEREMONY_KEYS} == after
    logged = [r for r in caplog.records if r.name.startswith("server.app.routes.simple")]
    assert len(logged) == 1, [r.getMessage() for r in logged]
    assert logged[0].exc_info is None
    assert "\n" not in logged[0].getMessage()


def test_a_refused_storage_name_is_still_a_400(app, monkeypatch, store):
    from server.app.storage.common import InvalidStorageIdentifier

    authenticator = Authenticator()
    client = app.test_client()
    _register(client, authenticator, counter=1)

    def _refused(*_args, **_kwargs):
        raise InvalidStorageIdentifier("Storage identifier contains a path separator")

    monkeypatch.setattr(store, "read_for_update", _refused)

    response = _authenticate(client, authenticator, counter=2)

    assert response.status_code == 400
    assert response.get_json()["error"].startswith("Invalid credential name: ")


@pytest.mark.parametrize(
    ("client_sign_count", "counter", "status"),
    [(None, 5, 200), (7, 5, 400), (7, 8, 200)],
    ids=["no-client-count-accepts", "client-count-still-rejects-a-regression", "client-count-increase-accepts"],
)
def test_no_stored_record_still_falls_back_to_the_client_count(
    app, monkeypatch, store, saves, client_sign_count, counter, status
):
    authenticator = Authenticator()
    client = app.test_client()
    _register(client, authenticator, counter=10)
    saves.clear()
    # The read works and finds nothing for this credential.
    monkeypatch.setattr(store, "read_for_update", lambda *_a, **_k: ([], None))

    response = _authenticate(client, authenticator, counter=counter, client_sign_count=client_sign_count)

    assert response.status_code == status, response.get_json()
    if status == 400:
        assert response.get_json()["signCountStatus"] == "regressed"
    # No record to advance, so nothing is written.
    assert saves == []


def test_a_readable_stored_counter_is_checked_and_advanced(app, store, saves):
    authenticator = Authenticator()
    client = app.test_client()
    _register(client, authenticator, counter=10)
    saves.clear()

    rejected = _authenticate(client, authenticator, counter=5)
    accepted = _authenticate(client, authenticator, counter=11)

    assert rejected.status_code == 400
    assert rejected.get_json()["signCountStatus"] == "regressed"
    assert accepted.status_code == 200, accepted.get_json()
    assert accepted.get_json()["signCount"] == 11
    assert len(saves) == 1
