"""Two concurrent authentications cannot both advance the counter to the same value.

The signature counter check is read-then-write. Two assertions carrying the
same counter -- which is what a cloned authenticator produces -- used to pass
together when both read the stored counter before either saved it. The save is
now compare-and-swap: the loser reads again, is checked against the counter the
winner stored, and is rejected.

Everything here is real: genuine signatures, the real local credential store in
a temporary directory, and two requests running at once in two threads. A
barrier holds each request just after it has read the stored counter until the
other has read it too, so the race is forced rather than hoped for.
"""
from __future__ import annotations

import threading

import pytest

from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    assertion_payload,
    registration_payload,
    unb64u,
)

EMAIL = "user@example.com"


@pytest.fixture
def store(monkeypatch, tmp_path, storage_module, device_logs_module):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setattr(storage_module, "_LOCAL_CREDENTIAL_BASE", str(tmp_path / "credentials"))
    monkeypatch.setattr(storage_module, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(tmp_path / "legacy"))
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)
    return storage_module


def _register(client, authenticator, counter):
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        f"/api/register/complete?email={EMAIL}",
        json=registration_payload(authenticator, challenge=challenge, counter=counter),
        headers={"Origin": ORIGIN},
    )
    assert complete.status_code == 200, complete.get_json()


def _begin(client, authenticator):
    begin = client.post(
        f"/api/authenticate/begin?email={EMAIL}", json={"credentials": [authenticator.stored_credential_entry()]}
    )
    assert begin.status_code == 200, begin.get_json()
    return unb64u(begin.get_json()["publicKey"]["challenge"])


def _stored_counter(store, root, authenticator):
    (session_id,) = [entry.name for entry in (root / "credentials").iterdir()]
    records = store.readkey(EMAIL, session_id=session_id)
    (record,) = [r for r in records if bytes(r["credential_data"].credential_id) == authenticator.credential_id]
    return record["sign_count"]


def test_two_authentications_with_the_same_counter_cannot_both_succeed(app, monkeypatch, store, simple_module, tmp_path):
    from server.app.routes.simple import authentication

    authenticator = Authenticator()
    first, second = app.test_client(), app.test_client()
    _register(first, authenticator, counter=5)
    # The same browser session, so the same server-side records.
    second.set_cookie("session", first.get_cookie("session").value)
    challenges = [_begin(first, authenticator), _begin(second, authenticator)]

    both_have_read = threading.Barrier(2, timeout=10)
    reads = []
    original = authentication.load_server_records

    def _read_then_wait(uname):
        loaded = original(uname)
        reads.append(loaded)
        if len(reads) <= 2:
            both_have_read.wait()
        return loaded

    monkeypatch.setattr(authentication, "load_server_records", _read_then_wait)

    responses = [None, None]

    def _complete(index, client):
        responses[index] = client.post(
            f"/api/authenticate/complete?email={EMAIL}",
            json=assertion_payload(authenticator, challenge=challenges[index], counter=6),
            headers={"Origin": ORIGIN},
        )

    threads = [threading.Thread(target=_complete, args=(i, c)) for i, c in enumerate((first, second))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    statuses = sorted(response.status_code for response in responses)
    assert statuses == [200, 400], [r.get_json() for r in responses]
    loser = next(r for r in responses if r.status_code == 400).get_json()
    assert loser["signCountStatus"] == "regressed"
    assert "stored 6, received 6" in loser["error"]
    # The loser read again after losing: three reads, not two.
    assert len(reads) == 3
    assert _stored_counter(store, tmp_path, authenticator) == 6


def test_losing_the_race_twice_rejects_the_authentication(app, monkeypatch, store, simple_module):
    from server.app.routes.simple import authentication

    authenticator = Authenticator()
    client = app.test_client()
    _register(client, authenticator, counter=5)
    challenge = _begin(client, authenticator)
    attempts = []

    def _always_lose(name, key, version, *, session_id=None):
        attempts.append(version)
        return False

    monkeypatch.setattr(authentication.credentials, "save_if_unchanged", _always_lose)

    response = client.post(
        f"/api/authenticate/complete?email={EMAIL}",
        json=assertion_payload(authenticator, challenge=challenge, counter=6),
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 409
    assert response.get_json()["error"].startswith("The stored signature counter changed during authentication")
    assert len(attempts) == 2


def test_an_uncontended_authentication_saves_its_counter_once(app, monkeypatch, store, simple_module):
    from server.app.routes.simple import authentication

    authenticator = Authenticator()
    client = app.test_client()
    _register(client, authenticator, counter=5)
    challenge = _begin(client, authenticator)
    saves = []
    original = authentication.credentials.save_if_unchanged

    def _counting(*args, **kwargs):
        saves.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(authentication.credentials, "save_if_unchanged", _counting)

    response = client.post(
        f"/api/authenticate/complete?email={EMAIL}",
        json=assertion_payload(authenticator, challenge=challenge, counter=6),
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200, response.get_json()
    assert saves == [EMAIL]
