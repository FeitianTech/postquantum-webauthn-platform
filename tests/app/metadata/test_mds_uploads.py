"""``mds.uploads``: a visitor's uploaded metadata statements, saved, listed, deleted and shown.

Each test stores in a session metadata directory of its own. A storage call that
fails is stood in for by a raising one: what a full disk or a lost bucket does.
"""

from __future__ import annotations

import json

import pytest

from server.app import visitor_session
from server.app.mds import uploads as mds_uploads
from server.app.storage import common as storage_common
from server.app.storage import session_metadata

SESSION = "session-a"
STATEMENT = {"aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "metadataStatement": {"description": "Uploaded"}}


def _fail(*_args, **_kwargs):
    raise OSError("storage unavailable")


@pytest.fixture
def storage(monkeypatch, tmp_path, metadata_state):
    root = tmp_path / "session-metadata"
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(root))
    # Saving schedules the idle-namespace sweep; none runs in a test.
    monkeypatch.setattr(visitor_session, "schedule_cleanup", lambda: None)
    return root


@pytest.fixture
def in_request(make_app):
    with make_app().test_request_context("/"):
        yield


def _stored(storage, payload=STATEMENT, info=None) -> str:
    directory = storage / SESSION
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "stored.json").write_text(json.dumps(payload))
    if info is not None:
        (directory / "stored.json.meta.json").write_text(info)
    return "stored.json"


def test_an_upload_whose_storage_cannot_be_prepared_fails(storage, in_request, monkeypatch, tmp_path):
    (tmp_path / "a-file").write_text("")
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "a-file"))

    with pytest.raises(NotADirectoryError):
        mds_uploads.save_session_metadata_item(STATEMENT)


def test_a_statement_json_cannot_hold_is_refused(storage, in_request):
    with pytest.raises(ValueError, match="Metadata JSON contains unsupported types"):
        mds_uploads.save_session_metadata_item({**STATEMENT, "extra": object()})


def test_an_upload_whose_info_cannot_be_written_or_time_read_is_still_saved(storage, in_request, monkeypatch):
    write_file = session_metadata.write_file

    def _payload_only(directory, filename, *args, **kwargs):
        if filename.endswith(".meta.json"):
            raise OSError("info not written")
        return write_file(directory, filename, *args, **kwargs)

    monkeypatch.setattr(session_metadata, "write_file", _payload_only)
    monkeypatch.setattr(session_metadata, "file_mtime", _fail)

    saved = mds_uploads.save_session_metadata_item(STATEMENT, original_filename="demo.json")

    assert (saved.original_filename, saved.mtime) == ("demo.json", None)
    assert [item.filename for item in mds_uploads.list_session_metadata_items(visitor_session.current_id())] == [saved.filename]


@pytest.mark.parametrize("info", [None, "[]", "{not json"])
def test_an_upload_without_a_readable_info_file_is_listed_without_its_names(storage, info):
    _stored(storage, info=info)

    (item,) = mds_uploads.list_session_metadata_items(SESSION)

    assert (item.uploaded_at, item.original_filename) == (None, None)


def test_an_info_file_that_cannot_be_read_is_none(storage, monkeypatch):
    _stored(storage, info=json.dumps({"original_filename": "demo.json"}))
    read_file = session_metadata.read_file
    monkeypatch.setattr(
        session_metadata, "read_file", lambda directory, name: _fail() if name.endswith(".meta.json") else read_file(directory, name)
    )
    monkeypatch.setattr(session_metadata, "file_mtime", _fail)

    (item,) = mds_uploads.list_session_metadata_items(SESSION)

    assert (item.original_filename, item.mtime) == (None, None)


def test_a_namespace_that_is_not_one_lists_nothing(storage):
    _stored(storage)

    assert mds_uploads.list_session_metadata_items("../escape") == []


def test_a_namespace_whose_uploads_cannot_be_listed_raises_rather_than_listing_none(storage, monkeypatch):
    _stored(storage)
    (storage / SESSION / "stored.json").unlink()
    (storage / SESSION).rmdir()
    # A file where the namespace's folder should be: the store cannot be read.
    (storage / SESSION).write_text("")

    with pytest.raises(storage_common.StorageReadError):
        mds_uploads.list_session_metadata_items(SESSION)


def test_deleting_from_a_namespace_that_is_not_one_or_cannot_be_read_deletes_nothing(storage, monkeypatch):
    stored = _stored(storage)

    assert mds_uploads.delete_session_metadata_item(stored, session_id="../escape") is False
    monkeypatch.setattr(session_metadata, "file_exists", _fail)
    assert mds_uploads.delete_session_metadata_item(stored, session_id=SESSION) is False
    assert (storage / SESSION / stored).exists()


def test_an_info_file_that_cannot_be_deleted_does_not_keep_the_upload(storage, monkeypatch):
    stored = _stored(storage, info="{}")
    delete_file = session_metadata.delete_file

    def _payload_only(directory, name, *, missing_ok=True):
        if name.endswith(".meta.json"):
            raise OSError("info not deleted")
        return delete_file(directory, name, missing_ok=missing_ok)

    monkeypatch.setattr(session_metadata, "delete_file", _payload_only)

    assert mds_uploads.delete_session_metadata_item(stored, session_id=SESSION) is True
    assert not (storage / SESSION / stored).exists()


@pytest.mark.parametrize("filename", [123, "   ", ".hidden.json", "nested/entry.json", "entry.txt"])
def test_a_name_that_is_no_upload_is_refused(storage, filename):
    with pytest.raises(ValueError, match="Invalid metadata filename"):
        mds_uploads.delete_session_metadata_item(filename, session_id=SESSION)


def test_an_upload_without_its_times_is_shown_with_its_name_only():
    item = mds_uploads.SessionMetadataItem(
        filename="stored.json", payload={"metadataStatement": {}}, legal_header="Legal", entry=None,
        uploaded_at=None, original_filename=None, mtime=None,
    )

    assert mds_uploads.serialize_session_metadata_item(item) == {
        "entry": {"metadataStatement": {}},
        "source": {"storedFilename": "stored.json"},
        "legalHeader": "Legal",
    }


def test_no_session_names_no_directory():
    # Every caller has a session by then; a direct call gives it none.
    assert mds_uploads._session_metadata_directory("") is None


def test_an_emptied_namespace_that_cannot_be_pruned_still_has_its_upload_deleted(storage, monkeypatch):
    stored = _stored(storage)
    monkeypatch.setattr(session_metadata, "prune_session", _fail)

    assert mds_uploads.delete_session_metadata_item(stored, session_id=SESSION) is True
    assert not (storage / SESSION / stored).exists()


def test_saved_metadata_info_keeps_json_objects_and_refuses_malformed_json(metadata_state, monkeypatch):
    monkeypatch.setattr(session_metadata, 'read_file', lambda _sid, _name: b'{"uploaded_at":"now"}')
    assert mds_uploads._load_session_metadata_info('session', 'entry.meta.json') == {'uploaded_at': 'now'}
    monkeypatch.setattr(session_metadata, 'read_file', lambda _sid, _name: b'not-json')
    assert mds_uploads._load_session_metadata_info('session', 'entry.meta.json') == {}
