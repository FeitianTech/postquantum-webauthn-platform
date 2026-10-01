"""A store read that fails is an error, never "fewer credentials".

Three cases, told apart everywhere the store reads:

- not found: nothing is stored there, which is fine;
- unreadable, because of an I/O or Cloud Storage error: ``StorageReadError``;
- undecodable content: a warning naming the file or object (never its content),
  and the copy skipped.

``readkey`` used to swallow a failed read and answer ``[]``, which looked like a
user with no credentials.

Both backends, the real store: a temporary directory, or a fake bucket. A local
read is made to fail by putting a directory where the file belongs, so open()
fails the way a real I/O error does (this holds for root too, unlike chmod).
"""
from __future__ import annotations

import logging
import os

import pytest

from server.app.storage import credentials as storage_credentials
from server.app.storage import record_format
from server.app.storage.common import StorageReadError

from . import fake_gcs

SESSION = "session-read-errors"
NAME = "alice@example.com"


def _records(tag):
    return record_format.encode_records([{"credential_data": tag}])


class _Local:
    def __init__(self, store, root):
        self.store = store
        self.root = root

    def _current(self, name):
        return self.store._local_filename(name, SESSION, create=True)

    def put_current(self, name, data):
        with open(self._current(name), "wb") as handle:
            handle.write(data)
        return self._current(name)

    def holds(self, source):
        with open(source, "rb") as handle:
            return handle.read()

    def break_current(self, name):
        os.makedirs(self._current(name))


class _Gcs:
    def __init__(self, store, bucket):
        self.store = store
        self.bucket = bucket

    def put_current(self, name, data):
        blob = self.store._credential_blob(name, SESSION)
        self.bucket.put(blob, data)
        return blob

    def holds(self, source):
        return self.bucket.objects[source][0]

    def break_current(self, name):
        self.bucket.failing[self.put_current(name, _records("unreachable"))] = fake_gcs.ServiceUnavailable("503")

@pytest.fixture(params=["local", "gcs"])
def backend(request, monkeypatch, tmp_path):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(tmp_path / "credentials"))
    if request.param == "gcs":
        return _Gcs(storage_credentials, fake_gcs.install(monkeypatch, storage_credentials))
    return _Local(storage_credentials, tmp_path)


# --------------------------------------------------------------------------
# unreadable: raise
# --------------------------------------------------------------------------


def test_the_error_names_the_copy_and_keeps_its_cause(backend):
    backend.break_current(NAME)

    with pytest.raises(StorageReadError) as raised:
        backend.store.readkey(NAME, session_id=SESSION)

    assert "alice@example.com_credential_data.json" in str(raised.value)
    assert raised.value.__cause__ is not None


# --------------------------------------------------------------------------
# not found: fine
# --------------------------------------------------------------------------


def test_nothing_stored_is_not_an_error(backend):
    assert backend.store.readkey(NAME, session_id=SESSION) == []
    assert backend.store.read_for_update(NAME, session_id=SESSION)[0] == []


# --------------------------------------------------------------------------
# undecodable: log by name, skip
# --------------------------------------------------------------------------

_SECRET = b"SECRET-CONTENT-7f3a"
_UNDECODABLE = [
    pytest.param(b"", id="empty"),
    pytest.param(b"not json " + _SECRET, id="not-json"),
    pytest.param(b'{"secret": "' + _SECRET + b'"}', id="json-but-not-a-credential-list"),
    pytest.param(b'{"credentials": [{"__t": "bytes", "__v": "' + _SECRET + b'!!"}]}', id="undecodable-json-value"),
]


@pytest.mark.parametrize("content", _UNDECODABLE)
def test_an_undecodable_copy_is_named_and_skipped(backend, caplog, content):
    source = backend.put_current(NAME, content)

    with caplog.at_level(logging.WARNING, logger="server.app.storage"):
        assert backend.store.readkey(NAME, session_id=SESSION) == []

    warnings = [record.getMessage() for record in caplog.records if record.name.startswith("server.app.storage")]
    assert len(warnings) == 1, warnings
    assert os.path.basename(source) in warnings[0]
    assert "SECRET" not in warnings[0]


def test_readkey_skips_an_undecodable_copy_with_a_warning(backend, caplog):
    source = backend.put_current(NAME, b"not json " + _SECRET)

    with caplog.at_level(logging.WARNING, logger="server.app.storage"):
        assert backend.store.readkey(NAME, session_id=SESSION) == []

    (warning,) = [r.getMessage() for r in caplog.records if r.name.startswith("server.app.storage")]
    assert os.path.basename(source) in warning
    assert "SECRET" not in warning


def test_read_for_update_refuses_to_replace_a_current_copy_it_cannot_decode(backend):
    # Skipping it here would hand the caller [] and let its save overwrite the
    # copy unread; the simple routes answer an error instead.
    backend.put_current(NAME, b"not json")

    with pytest.raises(backend.store.CredentialsUndecodable):
        backend.store.read_for_update(NAME, session_id=SESSION)
