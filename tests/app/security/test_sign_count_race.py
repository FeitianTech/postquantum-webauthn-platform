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

from server.app.routes.simple import stored_sign_count
from server.app.storage import credentials as storage_credentials

from .. import visitor_namespace
from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    assertion_payload,
    register_simple,
    simple_complete_body,
    unb64u,
)

EMAIL = "user@example.com"


def _begin(client, authenticator):
    begin = client.post(
        f"/api/authenticate/begin?email={EMAIL}", json={"credentials": [authenticator.stored_credential_entry()]}
    )
    assert begin.status_code == 200, begin.get_json()
    return unb64u(begin.get_json()["publicKey"]["challenge"])


def _stored_counter(root, authenticator):
    (session_id,) = [entry.name for entry in (root / "credentials").iterdir() if entry.is_dir()]
    records = storage_credentials.readkey(EMAIL, session_id=session_id)
    (record,) = [r for r in records if bytes(r["credential_data"].credential_id) == authenticator.credential_id]
    return record["sign_count"]


def test_two_authentications_with_the_same_counter_cannot_both_succeed(app, monkeypatch, credential_store, tmp_path):
    authenticator = Authenticator()
    first, second = app.test_client(), app.test_client()
    register_simple(first, authenticator, counter=5)
    # The same browser, so the same namespace and server-side records.
    visitor_namespace.give(second, visitor_namespace.of(first))
    challenges = [_begin(first, authenticator), _begin(second, authenticator)]

    both_have_read = threading.Barrier(2, timeout=10)
    reads = []
    original = stored_sign_count.load_server_records

    def _read_then_wait(uname):
        loaded = original(uname)
        reads.append(loaded)
        if len(reads) <= 2:
            both_have_read.wait()
        return loaded

    monkeypatch.setattr(stored_sign_count, "load_server_records", _read_then_wait)

    responses = [None, None]

    def _complete(index, client):
        responses[index] = client.post(
            f"/api/authenticate/complete?email={EMAIL}",
            json=simple_complete_body(
                assertion_payload(authenticator, challenge=challenges[index], counter=6),
                [authenticator.stored_credential_entry()],
            ),
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
    assert _stored_counter(tmp_path, authenticator) == 6


def test_losing_the_race_twice_rejects_the_authentication(app, monkeypatch, credential_store):
    authenticator = Authenticator()
    client = app.test_client()
    register_simple(client, authenticator, counter=5)
    challenge = _begin(client, authenticator)
    attempts = []

    def _always_lose(name, key, version, *, session_id=None):
        attempts.append(version)
        return False

    monkeypatch.setattr(storage_credentials, "save_if_unchanged", _always_lose)

    response = client.post(
        f"/api/authenticate/complete?email={EMAIL}",
        json=simple_complete_body(
            assertion_payload(authenticator, challenge=challenge, counter=6), [authenticator.stored_credential_entry()]
        ),
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 409
    assert response.get_json()["error"].startswith("The stored signature counter changed during authentication")
    assert len(attempts) == 2


def test_an_uncontended_authentication_saves_its_counter_once(app, monkeypatch, credential_store):
    authenticator = Authenticator()
    client = app.test_client()
    register_simple(client, authenticator, counter=5)
    challenge = _begin(client, authenticator)
    saves = []
    original = storage_credentials.save_if_unchanged

    def _counting(*args, **kwargs):
        saves.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(storage_credentials, "save_if_unchanged", _counting)

    response = client.post(
        f"/api/authenticate/complete?email={EMAIL}",
        json=simple_complete_body(
            assertion_payload(authenticator, challenge=challenge, counter=6), [authenticator.stored_credential_entry()]
        ),
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200, response.get_json()
    assert saves == [EMAIL]
