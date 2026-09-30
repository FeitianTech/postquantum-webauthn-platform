"""The credential store says when it failed, instead of answering as if nothing were stored.

readkey raises when it cannot read a copy, rather than answering "nothing stored
for this name".
"""
from __future__ import annotations

import os

import pytest

_SESSION = "session-failures"


@pytest.fixture
def local_store(monkeypatch, tmp_path, storage_module):
    root = tmp_path / "session-credentials"
    root.mkdir()
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(root))
    monkeypatch.setattr(storage_module, "_using_gcs", lambda: False)
    return storage_module


def _unreadable(store, name):
    # A directory where the file belongs: open() fails as on a real I/O error.
    os.makedirs(store._local_filename(name, _SESSION, create=True))


def test_a_copy_the_store_cannot_read_raises_instead_of_reading_as_empty(local_store):
    from server.app.storage.common import StorageReadError

    _unreadable(local_store, "alice@example.com")

    # An empty list would say "nothing stored for alice".
    with pytest.raises(StorageReadError):
        local_store.readkey("alice@example.com", session_id=_SESSION)
