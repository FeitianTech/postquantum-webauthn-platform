"""A save that read a legacy copy cannot write it back after a delete.

When a user has no current (session-scoped JSON) copy, ``read_for_update``
answers with a legacy copy's records -- a pre-session file or object, or a
``.pkl`` -- and the current copy's version, which is "there is none". A delete
between that read and the save removed the legacy copy (and the current copy,
if another save had made one), so "there is none" was true again: the save
matched and wrote the deleted records back beside its own. ``delkey`` now
leaves the current copy in place, holding no records, whenever it deleted
anything; that version cannot match it, so the save loses, reads again, and
stores its own record alone.

Everything is real: genuine registrations, the real store (a temporary
directory, or a fake GCS bucket with object generations) and a real delete
request. The registration is held just after its read until the delete has
answered, so the race is forced rather than hoped for.
"""
from __future__ import annotations

import os
import pickle
import threading

import pytest

from ..storage import fake_gcs
from .ceremony_helpers import ORIGIN, Authenticator, registration_payload, unb64u

EMAIL = "user@example.com"
SESSION = "session-legacy-race"


@pytest.fixture(params=["local", "gcs"])
def backend(request, monkeypatch, tmp_path, storage_module, device_logs_module):
    from server.app.storage import session_metadata

    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setattr(storage_module, "_LOCAL_CREDENTIAL_BASE", str(tmp_path / "credentials"))
    monkeypatch.setattr(storage_module, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(tmp_path / "legacy"))
    monkeypatch.setattr(storage_module, "basepath", str(tmp_path / "flat"))
    (tmp_path / "flat").mkdir()
    monkeypatch.setattr(session_metadata, "SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)
    bucket = fake_gcs.install(monkeypatch, storage_module) if request.param == "gcs" else None
    return request.param, storage_module, bucket


def _move_to_legacy(backend, session_id):
    """Turn the user's current copy into a pre-session one, as an old deployment left it."""

    kind, store, bucket = backend
    if kind == "gcs":
        current = store._credential_blob(EMAIL, session_id)
        legacy = store._legacy_credential_blob(EMAIL)
        bucket.objects[legacy] = bucket.objects.pop(current)
        return
    current = store._local_filename(EMAIL, session_id)
    legacy = store._local_filename(EMAIL, session_id, create=True, base=store._LEGACY_LOCAL_CREDENTIAL_BASE)
    os.replace(current, legacy)


def _put_session_pickle(backend, session_id, records):
    """A ``.pkl`` in the session's own folder, as the store wrote before it wrote JSON."""

    kind, store, bucket = backend
    payload = pickle.dumps(records)
    if kind == "gcs":
        bucket.put(store._credential_blob(EMAIL, session_id, suffix=store._PICKLE_SUFFIX), payload)
        return
    path = store._local_filename(EMAIL, session_id, create=True, suffix=store._PICKLE_SUFFIX)
    with open(path, "wb") as handle:
        handle.write(payload)


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


def _session_id(client) -> str:
    from server.app.webauthn import metadata

    with client.session_transaction() as session:
        return session[metadata._SESSION_METADATA_SESSION_KEY]


def _stored_ids(store, session_id) -> list[bytes]:
    return sorted(bytes(r["credential_data"].credential_id) for r in store.readkey(EMAIL, session_id=session_id))


def test_a_registration_racing_a_delete_does_not_bring_back_the_legacy_credentials(app, monkeypatch, backend, simple_module):
    _kind, store, _bucket = backend
    registering = app.test_client()
    old = Authenticator(credential_id=b"\x01" * 32)
    assert _complete(registering, old, _begin(registering)).status_code == 200
    session_id = _session_id(registering)
    _move_to_legacy(backend, session_id)
    assert _stored_ids(store, session_id) == [old.credential_id]

    new = Authenticator(credential_id=b"\x02" * 32)
    challenge = _begin(registering)
    has_read, delete_answered = threading.Event(), threading.Event()
    original = store.read_for_update

    def _read_then_hold(*args, **kwargs):
        loaded = original(*args, **kwargs)
        if not has_read.is_set():
            has_read.set()
            assert delete_answered.wait(10)
        return loaded

    monkeypatch.setattr(store, "read_for_update", _read_then_hold)
    responses = []
    registration = threading.Thread(target=lambda: responses.append(_complete(registering, new, challenge)))
    registration.start()
    assert has_read.wait(10)

    deleting = app.test_client()
    deleting.set_cookie("session", registering.get_cookie("session").value)
    deleted = deleting.post("/api/deletepub", json={"email": EMAIL})
    delete_answered.set()
    registration.join(20)

    assert deleted.status_code == 200, deleted.get_json()
    assert [response.status_code for response in responses] == [200], [r.get_json() for r in responses]
    # The deleted credential stays deleted; the one registered after it is kept.
    assert _stored_ids(store, session_id) == [new.credential_id]


def test_a_save_from_a_legacy_read_loses_to_a_delete_after_another_save(backend):
    """The version "there is no current copy" must not come back true after a delete.

    Another save made the current copy and dropped the session ``.pkl`` it
    replaced; the delete then found no legacy copy at all. Removing the current
    copy would make "there is none" true again for the first reader, whose
    records are the deleted ``.pkl``'s.
    """

    _kind, store, _bucket = backend
    _put_session_pickle(backend, SESSION, [{"credential_data": "legacy"}])

    first_records, first_version = store.read_for_update(EMAIL, session_id=SESSION)
    second_records, second_version = store.read_for_update(EMAIL, session_id=SESSION)
    assert first_records == second_records == [{"credential_data": "legacy"}]
    assert store.save_if_unchanged(EMAIL, second_records + [{"credential_data": "second"}], second_version, session_id=SESSION)
    store.delkey(EMAIL, session_id=SESSION)

    assert not store.save_if_unchanged(EMAIL, first_records + [{"credential_data": "first"}], first_version, session_id=SESSION)
    assert store.readkey(EMAIL, session_id=SESSION) == []

    # The loser reads again and keeps its own record alone.
    records, version = store.read_for_update(EMAIL, session_id=SESSION)
    assert records == []
    assert store.save_if_unchanged(EMAIL, records + [{"credential_data": "first"}], version, session_id=SESSION)
    assert store.readkey(EMAIL, session_id=SESSION) == [{"credential_data": "first"}]


def test_a_deleted_user_is_not_listed_and_has_nothing_to_download(app, backend, simple_module):
    _kind, store, _bucket = backend
    client = app.test_client()
    assert _complete(client, Authenticator(), _begin(client)).status_code == 200
    session_id = _session_id(client)

    assert client.post("/api/deletepub", json={"email": EMAIL}).status_code == 200

    assert store.readkey(EMAIL, session_id=session_id) == []
    assert list(store.iter_credentials(session_id=session_id)) == []
    assert client.get("/api/credentials").get_json() == {"credentials": []}
    assert client.get(f"/api/downloadcred?email={EMAIL}").status_code == 404


def test_deleting_a_name_with_nothing_stored_writes_nothing(backend):
    kind, store, bucket = backend

    store.delkey("nobody@example.com", session_id=SESSION)

    if kind == "gcs":
        assert bucket.objects == {}
    else:
        assert not os.path.exists(store._local_directory(SESSION))
