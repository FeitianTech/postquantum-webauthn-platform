"""Concurrent registrations for one user all keep their credential.

Simple registration reads the user's stored credentials, appends the new one and
writes the list back. Done as a plain read then write, two registrations that
both read before either wrote each wrote back a list without the other's
credential, so one was lost. The write is now compare-and-swap: a registration
that loses re-reads the list, which now holds the winner's credential, and
appends to that.

Everything is real: genuine registrations, the real store (a temporary
directory, or a fake GCS bucket with object generations), and eight requests
completing at once in eight threads. A barrier holds each request just before
its first write until all eight have read, so the race is forced rather than
hoped for.
"""
from __future__ import annotations

import threading

import pytest

from ..storage import fake_gcs
from .ceremony_helpers import ORIGIN, Authenticator, registration_payload, unb64u

EMAIL = "user@example.com"
WRITERS = 8
# The route's retry bound: eight writers racing for one user each lose at most seven times.
SAVE_ATTEMPTS = 8


@pytest.fixture(params=["local", "gcs"])
def store(request, monkeypatch, tmp_path, storage_module, device_logs_module):
    from server.app.storage import session_metadata

    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setattr(storage_module, "_LOCAL_CREDENTIAL_BASE", str(tmp_path / "credentials"))
    monkeypatch.setattr(storage_module, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(tmp_path / "legacy"))
    monkeypatch.setattr(storage_module, "basepath", str(tmp_path / "flat"))
    monkeypatch.setattr(session_metadata, "SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)
    if request.param == "gcs":
        fake_gcs.install(monkeypatch, storage_module)
    return storage_module


def _begin(client) -> bytes:
    begin = client.post(f"/api/register/begin?email={EMAIL}", json={"credentials": []})
    assert begin.status_code == 200, begin.get_json()
    return unb64u(begin.get_json()["publicKey"]["challenge"])


def _complete(client, authenticator, challenge):
    return client.post(
        f"/api/register/complete?email={EMAIL}",
        json=registration_payload(authenticator, challenge=challenge),
        headers={"Origin": ORIGIN},
    )


def _register(client, authenticator):
    response = _complete(client, authenticator, _begin(client))
    assert response.status_code == 200, response.get_json()
    return response


def _stored_ids(store, client) -> list[bytes]:
    from server.app.webauthn import metadata

    with client.session_transaction() as session:
        namespace = session[metadata._SESSION_METADATA_SESSION_KEY]
    return sorted(bytes(record["credential_data"].credential_id) for record in store.readkey(EMAIL, session_id=namespace))


def test_eight_registrations_for_one_user_at_once_all_keep_their_credential(app, monkeypatch, store, simple_module):
    first = app.test_client()
    existing = Authenticator(credential_id=b"\x01" * 32)
    _register(first, existing)
    cookie = first.get_cookie("session").value

    authenticators = [Authenticator(credential_id=bytes([0x10 + index]) * 32) for index in range(WRITERS)]
    clients = []
    for _authenticator in authenticators:
        client = app.test_client()
        client.set_cookie("session", cookie)
        clients.append(client)
    challenges = [_begin(client) for client in clients]

    all_have_read = threading.Barrier(WRITERS, timeout=10)
    held = threading.local()

    def _after_everyone_has_read(write):
        def _write(*args, **kwargs):
            if not getattr(held, "done", False):
                held.done = True
                all_have_read.wait()
            return write(*args, **kwargs)

        return _write

    # Both writes are wrapped: the plain save the old code made and the conditional one.
    monkeypatch.setattr(store, "savekey", _after_everyone_has_read(store.savekey))
    monkeypatch.setattr(store, "save_if_unchanged", _after_everyone_has_read(store.save_if_unchanged))

    responses = [None] * WRITERS

    def _run(index):
        responses[index] = _complete(clients[index], authenticators[index], challenges[index])

    threads = [threading.Thread(target=_run, args=(index,)) for index in range(WRITERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert [response.status_code for response in responses] == [200] * WRITERS, [r.get_json() for r in responses]
    expected = sorted([existing.credential_id] + [authenticator.credential_id for authenticator in authenticators])
    assert _stored_ids(store, first) == expected


def test_losing_every_race_rejects_the_registration_and_stores_nothing(app, monkeypatch, store, simple_module):
    attempts = []

    def _always_lose(name, key, version, *, session_id=None):
        attempts.append(version)
        return False

    monkeypatch.setattr(store, "save_if_unchanged", _always_lose)
    client = app.test_client()
    response = _complete(client, Authenticator(), _begin(client))

    assert response.status_code == 409
    assert response.get_json()["error"].startswith("The stored credentials changed while this one was being saved")
    assert len(attempts) == SAVE_ATTEMPTS
    assert _stored_ids(store, client) == []


def test_an_uncontended_registration_saves_once(app, monkeypatch, store, simple_module):
    saves = []
    original = store.save_if_unchanged

    def _counting(*args, **kwargs):
        saves.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "save_if_unchanged", _counting)
    client = app.test_client()
    authenticator = Authenticator()
    _register(client, authenticator)

    assert saves == [EMAIL]
    assert _stored_ids(store, client) == [authenticator.credential_id]


def test_a_save_that_landed_before_it_failed_counts_as_saved(app, monkeypatch, store, simple_module):
    original = store.save_if_unchanged

    def _lands_then_fails(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("connection reset after the write")

    monkeypatch.setattr(store, "save_if_unchanged", _lands_then_fails)
    client = app.test_client()
    authenticator = Authenticator()
    _register(client, authenticator)

    assert _stored_ids(store, client) == [authenticator.credential_id]


def test_a_save_that_failed_before_it_landed_is_an_error(app, monkeypatch, store, simple_module):
    def _fails(*_args, **_kwargs):
        raise OSError("bucket unreachable")

    monkeypatch.setattr(store, "save_if_unchanged", _fails)
    client = app.test_client()
    response = _complete(client, Authenticator(), _begin(client))

    assert response.status_code == 500
    assert response.get_json() == {"error": "Unable to persist registered credential."}
    assert _stored_ids(store, client) == []


def test_a_failed_read_is_an_error_not_an_empty_list_to_overwrite(app, monkeypatch, store, simple_module):
    client = app.test_client()
    first = Authenticator(credential_id=b"\x01" * 32)
    _register(client, first)

    def _unreadable(*_args, **_kwargs):
        raise OSError("transient read failure")

    monkeypatch.setattr(store, "read_for_update", _unreadable)
    response = _complete(client, Authenticator(credential_id=b"\x02" * 32), _begin(client))

    assert response.status_code == 500
    assert response.get_json() == {"error": "Unable to persist registered credential."}
    assert _stored_ids(store, client) == [first.credential_id]


def _break_the_current_copy(store, client, how: str):
    """Make the user's current copy unreadable (``"unreadable"``) or undecodable; return a repair."""

    import os

    from server.app.storage import cloud
    from server.app.webauthn import metadata

    with client.session_transaction() as session:
        namespace = session[metadata._SESSION_METADATA_SESSION_KEY]
    if store._using_gcs():
        bucket = cloud._ensure_bucket()
        blob = store._credential_blob(EMAIL, namespace)
        original = bucket.objects[blob][0]
        if how == "unreadable":
            bucket.failing[blob] = fake_gcs.ServiceUnavailable("503 at /secret/path")
            return bucket.failing.clear
        bucket.put(blob, b"not a credential record")

        def _restore_object():
            left = bucket.objects[blob][0]
            bucket.put(blob, original)
            return left

        return _restore_object
    path = store._local_filename(EMAIL, namespace)
    with open(path, "rb") as handle:
        original = handle.read()
    if how == "unreadable":
        # A directory where the file belongs: the read fails with an OSError.
        os.replace(path, f"{path}.aside")
        os.mkdir(path)

        def _repair():
            os.rmdir(path)
            os.replace(f"{path}.aside", path)

        return _repair
    with open(path, "wb") as handle:
        handle.write(b"not a credential record")

    def _restore():
        with open(path, "rb") as handle:
            left = handle.read()
        with open(path, "wb") as handle:
            handle.write(original)
        return left

    return _restore


@pytest.mark.parametrize("how", ["unreadable", "undecodable"])
def test_a_store_that_cannot_be_read_answers_503_and_saves_nothing(app, caplog, store, simple_module, how):
    import logging

    client = app.test_client()
    first = Authenticator(credential_id=b"\x01" * 32)
    _register(client, first)
    challenge = _begin(client)
    repair = _break_the_current_copy(store, client, how)

    with caplog.at_level(logging.INFO, logger="server.app"):
        response = _complete(client, Authenticator(credential_id=b"\x02" * 32), challenge)

    assert response.status_code == 503, response.get_json()
    body = response.get_json()
    assert list(body) == ["error"]
    assert "could not be read" in body["error"]
    assert "/secret/path" not in response.get_data(as_text=True)
    logged = [record for record in caplog.records if record.levelno >= logging.WARNING]
    assert len(logged) == 1, [record.getMessage() for record in logged]
    assert logged[0].exc_info is None
    left = repair()
    if how == "undecodable":
        # The copy nobody could read was not replaced.
        assert left == b"not a credential record"
    assert _stored_ids(store, client) == [first.credential_id]


def test_a_user_whose_only_copy_is_an_undecodable_pickle_is_answered_503_and_keeps_it(app, store, simple_module):
    from server.app.webauthn import metadata

    client = app.test_client()
    namespace = "namespace-with-an-old-pickle"
    with client.session_transaction() as session:
        session[metadata._SESSION_METADATA_SESSION_KEY] = namespace
    challenge = _begin(client)
    # No current copy: the user's only one is a session .pkl nobody can read.
    if store._using_gcs():
        from server.app.storage import cloud

        bucket = cloud._ensure_bucket()
        blob = store._credential_blob(EMAIL, namespace, suffix=store._PICKLE_SUFFIX)
        bucket.put(blob, b"not a credential record")

        def _left():
            return bucket.objects[blob][0]
    else:
        path = store._local_filename(EMAIL, namespace, create=True, suffix=store._PICKLE_SUFFIX)
        with open(path, "wb") as handle:
            handle.write(b"not a credential record")

        def _left():
            with open(path, "rb") as handle:
                return handle.read()

    response = _complete(client, Authenticator(credential_id=b"\x02" * 32), challenge)

    # Before: 200, a new current copy holding only the new credential, and the .pkl deleted.
    assert response.status_code == 503, response.get_json()
    assert _left() == b"not a credential record"
    assert _stored_ids(store, client) == []
