"""The credential store says when it failed, instead of answering as if nothing were stored.

delkey raises when a file it should delete stays, and readkey raises when it cannot
read a copy, rather than answering "nothing stored for this name".
"""
from __future__ import annotations

import os

import pytest

_SESSION = "session-failures"


@pytest.fixture
def local_store(monkeypatch, tmp_path, storage_module):
    root = tmp_path / "session-credentials"
    root.mkdir()
    monkeypatch.setattr(storage_module, "_LOCAL_CREDENTIAL_BASE", str(root))
    monkeypatch.setattr(storage_module, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(root))
    monkeypatch.setattr(storage_module, "basepath", str(tmp_path))
    monkeypatch.setattr(storage_module, "_using_gcs", lambda: False)
    return storage_module


def _legacy_copy(store, name):
    # The flat pre-session file: a copy delkey removes rather than empties.
    with open(store._legacy_local_filename(name), "wb") as handle:
        handle.write(store.record_format.encode_records([{"credential_data": "legacy"}]))


def test_delkey_raises_when_a_file_it_should_delete_stays(monkeypatch, local_store):
    local_store.savekey("alice", [{"credential_data": "x"}], session_id=_SESSION)
    _legacy_copy(local_store, "alice")
    real_remove = os.remove

    def _remove(path):
        if os.path.exists(path):
            raise PermissionError(f"read-only: {path}")
        real_remove(path)

    monkeypatch.setattr(local_store.os, "remove", _remove)

    with pytest.raises(PermissionError):
        local_store.delkey("alice", session_id=_SESSION)


def test_delkey_of_a_name_with_nothing_stored_is_not_an_error(local_store):
    local_store.delkey("nobody", session_id=_SESSION)


def _unreadable(store, name):
    # A directory where the file belongs: open() fails as on a real I/O error.
    os.makedirs(store._local_filename(name, _SESSION, create=True))


def test_a_copy_the_store_cannot_read_raises_instead_of_reading_as_empty(local_store):
    from server.app.storage.common import StorageReadError

    _unreadable(local_store, "alice@example.com")

    # An empty list would say "nothing stored for alice".
    with pytest.raises(StorageReadError):
        local_store.readkey("alice@example.com", session_id=_SESSION)
