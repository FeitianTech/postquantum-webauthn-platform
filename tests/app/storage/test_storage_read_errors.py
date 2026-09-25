"""A store read that fails is an error, never "fewer credentials".

Three cases, told apart everywhere the store reads:

- not found: nothing is stored there, which is fine;
- unreadable, because of an I/O or Cloud Storage error: ``StorageReadError``;
- undecodable content: a warning naming the file or object (never its content),
  the copy skipped, and counted where a caller asks for the count.

``readkey`` used to swallow a failed read of the current copy and fall through to
the legacy copy (stale) or to ``[]``; ``iter_credentials`` skipped an entry it
could not read, and a GCS listing that failed was a warning. Each looked like a
user with fewer credentials, or none.

Both backends, the real store: a temporary directory, or a fake bucket. A local
read is made to fail by putting a directory where the file belongs, so open()
fails the way a real I/O error does (this holds for root too, unlike chmod).
"""
from __future__ import annotations

import logging
import os
import shutil

import pytest

from server.app.storage import record_format
from server.app.storage.common import StorageReadError

from . import fake_gcs

SESSION = "session-read-errors"
NAME = "alice@example.com"
OTHER = "bob@example.com"


def _records(tag):
    return record_format.encode_records([{"credential_data": tag}])


class _Local:
    def __init__(self, store, root):
        self.store = store
        self.root = root

    def _current(self, name):
        return self.store._local_filename(name, SESSION, create=True)

    def _legacy(self, name):
        return self.store._local_filename(name, SESSION, create=True, base=self.store._LEGACY_LOCAL_CREDENTIAL_BASE)

    def put_current(self, name, data):
        with open(self._current(name), "wb") as handle:
            handle.write(data)
        return self._current(name)

    def put_legacy(self, name, data):
        with open(self._legacy(name), "wb") as handle:
            handle.write(data)
        return self._legacy(name)

    def put_session_pickle(self, name, data):
        path = self.store._local_filename(name, SESSION, create=True, suffix=self.store._PICKLE_SUFFIX)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def holds(self, source):
        with open(source, "rb") as handle:
            return handle.read()

    def break_current(self, name):
        os.makedirs(self._current(name))

    def break_legacy(self, name):
        os.makedirs(self._legacy(name))

    def break_listing(self):
        session_dir = os.path.dirname(self._current(NAME))
        shutil.rmtree(session_dir)
        # A file where the session directory belongs: listing it fails, and
        # that is not the same as there being no directory.
        with open(session_dir, "wb") as handle:
            handle.write(b"")


class _Gcs:
    def __init__(self, store, bucket):
        self.store = store
        self.bucket = bucket

    def put_current(self, name, data):
        blob = self.store._credential_blob(name, SESSION)
        self.bucket.put(blob, data)
        return blob

    def put_legacy(self, name, data):
        blob = self.store._legacy_credential_blob(name)
        self.bucket.put(blob, data)
        return blob

    def put_session_pickle(self, name, data):
        blob = self.store._credential_blob(name, SESSION, suffix=self.store._PICKLE_SUFFIX)
        self.bucket.put(blob, data)
        return blob

    def holds(self, source):
        return self.bucket.objects[source][0]

    def break_current(self, name):
        self.bucket.failing[self.put_current(name, _records("unreachable"))] = fake_gcs.ServiceUnavailable("503")

    def break_legacy(self, name):
        self.bucket.failing[self.put_legacy(name, _records("unreachable"))] = fake_gcs.ServiceUnavailable("503")

    def break_listing(self):
        def _unavailable(prefix="", max_results=None, delimiter=None):
            raise fake_gcs.ServiceUnavailable("503")

        self.bucket.list_blobs = _unavailable


@pytest.fixture(params=["local", "gcs"])
def backend(request, monkeypatch, tmp_path, storage_module):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setattr(storage_module, "_LOCAL_CREDENTIAL_BASE", str(tmp_path / "credentials"))
    monkeypatch.setattr(storage_module, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(tmp_path / "legacy"))
    monkeypatch.setattr(storage_module, "basepath", str(tmp_path / "flat"))
    (tmp_path / "flat").mkdir()
    if request.param == "gcs":
        return _Gcs(storage_module, fake_gcs.install(monkeypatch, storage_module))
    return _Local(storage_module, tmp_path)


# --------------------------------------------------------------------------
# unreadable: raise
# --------------------------------------------------------------------------


def test_readkey_does_not_fall_back_to_the_legacy_copy_when_the_current_one_cannot_be_read(backend):
    backend.put_legacy(NAME, _records("stale"))
    backend.break_current(NAME)

    with pytest.raises(StorageReadError):
        backend.store.readkey(NAME, session_id=SESSION)


def test_readkey_does_not_answer_empty_when_a_legacy_copy_cannot_be_read(backend):
    backend.break_legacy(NAME)

    with pytest.raises(StorageReadError):
        backend.store.readkey(NAME, session_id=SESSION)


def test_read_for_update_does_not_answer_empty_when_a_legacy_copy_cannot_be_read(backend):
    # Answering [] would let the save that follows replace the legacy records.
    backend.break_legacy(NAME)

    with pytest.raises(StorageReadError):
        backend.store.read_for_update(NAME, session_id=SESSION)


def test_iter_credentials_does_not_skip_an_entry_it_cannot_read(backend):
    backend.put_current(OTHER, _records("bob"))
    backend.break_current(NAME)

    with pytest.raises(StorageReadError):
        list(backend.store.iter_credentials(session_id=SESSION))


def test_a_listing_that_fails_is_an_error_not_an_empty_store(backend):
    backend.put_current(NAME, _records("alice"))
    backend.break_listing()

    with pytest.raises(StorageReadError) as raised:
        list(backend.store.iter_credentials(session_id=SESSION))
    if backend.store._using_gcs():
        # The bucket's own error, not a stand-in that could not take the call.
        assert isinstance(raised.value.__cause__, fake_gcs.ServiceUnavailable)


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
    assert list(backend.store.iter_credentials(session_id=SESSION)) == []


def test_readkey_still_reads_the_legacy_copy_when_there_is_no_current_one(backend):
    backend.put_legacy(NAME, _records("legacy"))

    assert backend.store.readkey(NAME, session_id=SESSION) == [{"credential_data": "legacy"}]


# --------------------------------------------------------------------------
# undecodable: log by name, skip, count
# --------------------------------------------------------------------------

_SECRET = b"SECRET-CONTENT-7f3a"
_UNDECODABLE = [
    pytest.param(b"", id="empty"),
    pytest.param(b"not json " + _SECRET, id="neither-json-nor-pickle"),
    pytest.param(b'{"secret": "' + _SECRET + b'"}', id="json-but-not-a-credential-list"),
    # A pickle naming a global outside the allowlist; the unpickler's own
    # message quotes that name, which comes from the content.
    pytest.param(b"csecretmodule\n" + _SECRET + b"\n.", id="refused-pickle"),
    pytest.param(b'{"credentials": [{"__t": "bytes", "__v": "' + _SECRET + b'!!"}]}', id="undecodable-json-value"),
]


@pytest.mark.parametrize("content", _UNDECODABLE)
def test_an_undecodable_entry_is_named_skipped_and_counted(backend, caplog, content):
    backend.put_current(OTHER, _records("bob"))
    source = backend.put_current(NAME, content)
    undecodable = []

    with caplog.at_level(logging.WARNING, logger="server.app.storage"):
        listed = list(backend.store.iter_credentials(session_id=SESSION, undecodable=undecodable))

    assert listed == [(OTHER, [{"credential_data": "bob"}])]
    assert undecodable == [NAME]
    warnings = [record.getMessage() for record in caplog.records if record.name.startswith("server.app.storage")]
    assert len(warnings) == 1, warnings
    assert os.path.basename(source) in warnings[0]
    assert "SECRET" not in warnings[0]
    assert "secretmodule" not in warnings[0]


def test_list_credentials_passes_the_count_on(backend):
    backend.put_current(NAME, b"not json")
    undecodable = []

    assert backend.store.list_credentials(session_id=SESSION, undecodable=undecodable) == {}
    assert undecodable == [NAME]


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
    backend.put_legacy(NAME, _records("stale"))
    backend.put_current(NAME, b"not json")

    with pytest.raises(backend.store.CredentialsUndecodable):
        backend.store.read_for_update(NAME, session_id=SESSION)


@pytest.mark.parametrize("copy", ["session pickle", "legacy"])
def test_read_for_update_refuses_to_replace_an_only_copy_it_cannot_decode(backend, copy):
    # With no current copy the save writes one: it would shadow this copy, and
    # remove a session .pkl, without anyone having read it.
    put = backend.put_session_pickle if copy == "session pickle" else backend.put_legacy
    source = put(NAME, b"not a credential record")

    with pytest.raises(backend.store.CredentialsUndecodable, match="Could not decode"):
        backend.store.read_for_update(NAME, session_id=SESSION)
    assert backend.holds(source) == b"not a credential record"
    # Reads that only show records still skip it.
    assert backend.store.readkey(NAME, session_id=SESSION) == []


def test_read_for_update_reads_an_only_legacy_copy_that_decodes(backend):
    backend.put_legacy(NAME, _records("legacy"))

    records, version = backend.store.read_for_update(NAME, session_id=SESSION)

    assert records == [{"credential_data": "legacy"}]
    assert backend.store.save_if_unchanged(NAME, [*records, {"credential_data": "new"}], version, session_id=SESSION)
