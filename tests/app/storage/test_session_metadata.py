"""``storage.session_metadata``: a visitor's uploaded metadata and last access.

On Cloud Storage the store runs over the in-memory bucket (``fake_gcs``), so what
is asserted is what the bucket holds: the objects under ``user-data/<session>/``.
On disk it runs over the test's own folder.
"""
from __future__ import annotations

import json
import logging
import os
import shutil

import pytest

from server.app.storage import common as storage_common
from server.app.storage import session_metadata as session_store

from . import fake_gcs

SESSION = "session-gcs"
METADATA = f"user-data/{SESSION}/metadata"
MARKER = f"user-data/{SESSION}/.last-access"


@pytest.fixture
def bucket(monkeypatch):
    return fake_gcs.install(monkeypatch, session_store)


def test_an_upload_is_kept_in_the_namespaces_metadata_folder_and_marks_its_last_access(bucket):
    session_store.write_file(SESSION, "entry.json", b"{}", content_type="application/json")

    assert bucket.objects[f"{METADATA}/entry.json"][0] == b"{}"
    assert bucket.content_types[f"{METADATA}/entry.json"] == "application/json"
    assert MARKER in bucket.objects
    assert session_store.file_exists(SESSION, "entry.json") is True
    assert session_store.file_exists(SESSION, "missing.json") is False
    assert session_store.read_file(SESSION, "entry.json") == b"{}"
    assert session_store.read_file(SESSION, "missing.json") is None
    assert session_store.file_mtime(SESSION, "entry.json") == bucket.updated[f"{METADATA}/entry.json"].timestamp()
    assert session_store.file_mtime(SESSION, "missing.json") is None


def test_an_upload_name_that_is_only_slashes_names_no_object(bucket):
    for name in ("", "///"):
        with pytest.raises(ValueError, match="Invalid metadata filename"):
            session_store.read_file(SESSION, name)

    assert bucket.objects == {}


def test_a_namespace_is_ensured_by_marking_its_last_access(bucket):
    session_store.ensure_session(SESSION)

    assert list(bucket.objects) == [MARKER]
    assert bucket.content_types[MARKER] == "application/json"


def test_the_last_access_is_the_markers_timestamp(bucket):
    session_store.touch_last_access(SESSION, timestamp=321.5)

    assert json.loads(bucket.objects[MARKER][0]) == {"timestamp": 321.5}
    assert session_store.resolve_last_access(SESSION) == 321.5


@pytest.mark.parametrize("marker", [b"not json", b'{"timestamp": "bad"}', b"[]", b""])
def test_a_marker_without_a_timestamp_gives_the_time_it_was_written(bucket, marker):
    bucket.put(MARKER, marker)

    assert session_store.resolve_last_access(SESSION) == bucket.updated[MARKER].timestamp()


def test_a_namespace_without_a_marker_has_no_last_access(bucket):
    assert session_store.resolve_last_access(SESSION) is None


def test_the_uploads_are_the_metadata_folders_files_without_markers_or_folders(bucket):
    for name in ("b.json", "a.json", ".last-access", "nested/", ""):
        bucket.put(f"{METADATA}/{name}", b"{}")
    bucket.put(f"user-data/{SESSION}/credentials/user_credential_data.json", b"{}")

    assert session_store.list_files(SESSION) == ["a.json", "b.json"]
    assert session_store.session_is_empty(SESSION) is False


def test_deleting_an_upload_keeps_the_namespace_marked(bucket):
    session_store.write_file(SESSION, "entry.json", b"{}")
    bucket.objects.pop(MARKER)

    session_store.delete_file(SESSION, "entry.json")

    assert session_store.list_files(SESSION) == []
    assert MARKER in bucket.objects
    session_store.delete_file(SESSION, "entry.json")
    with pytest.raises(fake_gcs.NotFound):
        session_store.delete_file(SESSION, "entry.json", missing_ok=False)


def test_deleting_a_namespace_removes_every_object_under_it_and_nothing_else(bucket):
    for name in ("metadata/a.json", "credentials/user_credential_data.json", ".last-access"):
        bucket.put(f"user-data/{SESSION}/{name}", b"{}")
    bucket.put("user-data/other/metadata/a.json", b"{}")

    session_store.delete_session(SESSION)

    assert list(bucket.objects) == ["user-data/other/metadata/a.json"]


def test_a_namespace_whose_objects_cannot_be_listed_is_not_deleted(bucket, monkeypatch, caplog):
    bucket.put(f"{METADATA}/a.json", b"{}")
    monkeypatch.setattr(bucket, "list_blobs", _refused)

    with caplog.at_level(logging.WARNING, logger=session_store.__name__):
        session_store.delete_session(SESSION)

    assert f"{METADATA}/a.json" in bucket.objects
    assert "Unable to enumerate metadata for deletion" in caplog.text


def test_the_namespaces_are_the_user_folders_folders(bucket):
    for session in ("s2", "s1"):
        bucket.put(f"user-data/{session}/metadata/a.json", b"{}")
    bucket.put("user-data/flat-file.json", b"{}")
    bucket.put("user-data//stray.json", b"{}")

    assert session_store.list_sessions() == ["s1", "s2"]


def test_namespaces_that_cannot_be_listed_are_none_and_said_so(bucket, monkeypatch, caplog):
    bucket.put("user-data/s1/metadata/a.json", b"{}")
    monkeypatch.setattr(bucket, "list_blobs", _refused)

    with caplog.at_level(logging.WARNING, logger=session_store.__name__):
        assert session_store.list_sessions() == []

    assert "Unable to list session metadata blobs" in caplog.text


def test_uploads_that_cannot_be_listed_raise_rather_than_seem_none(bucket, monkeypatch):
    monkeypatch.setattr(bucket, "list_blobs", _refused)

    with pytest.raises(storage_common.StorageReadError):
        session_store.list_files(SESSION)


def test_a_namespace_on_cloud_storage_is_never_pruned(bucket):
    bucket.put(MARKER, b"{}")

    session_store.prune_session(SESSION)

    assert MARKER in bucket.objects


@pytest.fixture
def on_disk(monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path))
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)
    return tmp_path


def test_on_disk_a_name_that_is_no_namespace_holds_nothing_and_changes_nothing(on_disk):
    (on_disk / "kept").mkdir()

    assert session_store.read_file("../kept", "entry.json") is None
    assert session_store.file_mtime("../kept", "entry.json") is None
    assert session_store.file_exists("../kept", "entry.json") is False
    assert session_store.list_files("../kept") == []
    assert session_store.resolve_last_access("../kept") is None
    session_store.touch_last_access("../kept")
    session_store.delete_file("../kept", "entry.json")
    session_store.delete_session("../kept")
    with pytest.raises(ValueError, match="Invalid session identifier"):
        session_store.write_file("../kept", "entry.json", b"{}")
    assert sorted(path.name for path in on_disk.iterdir()) == ["kept"]


def test_on_disk_the_store_and_a_namespace_are_made_on_the_first_write(on_disk, monkeypatch):
    base = on_disk / "not-made-yet"
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(base))

    assert session_store.list_sessions() == []
    assert session_store.file_exists("session-local", "entry.json") is False
    assert not base.exists()

    session_store.write_file("session-local", "entry.json", b"{}")

    assert (base / "session-local" / "entry.json").read_bytes() == b"{}"
    assert session_store.list_sessions() == ["session-local"]


def test_on_disk_a_store_that_cannot_be_made_refuses_the_write_and_says_so(on_disk, monkeypatch, caplog):
    (on_disk / "a-file").write_text("")
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(on_disk / "a-file"))

    with caplog.at_level(logging.ERROR, logger=session_store.__name__), pytest.raises(OSError):
        session_store.write_file("session-local", "entry.json", b"{}")

    assert "Failed to prepare session metadata directory" in caplog.text
    assert session_store.list_sessions() == []


def test_on_disk_the_namespaces_are_the_stores_visible_folders(on_disk):
    for name in ("s2", "s1", ".hidden"):
        (on_disk / name).mkdir()
    (on_disk / "file.txt").write_text("x")

    assert session_store.list_sessions() == ["s1", "s2"]


def test_on_disk_the_uploads_are_the_namespaces_visible_files(on_disk):
    session_store.write_file("session-local", "b.json", b"{}")
    session_store.write_file("session-local", "a.json", b"{}")
    (on_disk / "session-local" / "nested").mkdir()
    (on_disk / "session-local" / ".hidden.json").write_text("{}")

    assert session_store.list_files("session-local") == ["a.json", "b.json"]
    assert session_store.list_files("never-made") == []


def test_on_disk_a_namespace_that_is_a_file_cannot_be_listed(on_disk):
    (on_disk / "session-local").write_text("not a folder")

    with pytest.raises(storage_common.StorageReadError):
        session_store.list_files("session-local")


def test_on_disk_the_last_access_is_the_markers_time_or_else_the_newest_upload_or_the_folder(on_disk):
    session_store.touch_last_access("session-local", timestamp=321.0)
    assert session_store.resolve_last_access("session-local") == 321.0

    folder = on_disk / "session-local"
    (folder / ".last-access").unlink()
    for name, mtime in (("old.json", 10.0), ("new.json", 22.5), ("older.json", 5.0)):
        (folder / name).write_text("{}")
        os.utime(folder / name, (mtime, mtime))
    assert session_store.resolve_last_access("session-local") == 22.5

    for name in ("old.json", "new.json", "older.json"):
        (folder / name).unlink()
    os.utime(folder, (33.25, 33.25))
    assert session_store.resolve_last_access("session-local") == 33.25

    assert session_store.resolve_last_access("never-made") is None


def test_on_disk_a_marker_that_cannot_be_written_does_not_stop_the_upload(on_disk):
    (on_disk / "session-local" / ".last-access").mkdir(parents=True)

    session_store.touch_last_access("session-local")
    session_store.touch_last_access("session-local", timestamp=321.0)
    session_store.write_file("session-local", "entry.json", b"{}")

    assert session_store.read_file("session-local", "entry.json") == b"{}"


def test_on_disk_deleting_an_upload_that_is_not_there_fails_only_when_asked(on_disk):
    session_store.write_file("session-local", "entry.json", b"{}")
    (on_disk / "session-local" / "folder.json").mkdir()

    session_store.delete_file("session-local", "missing.json")
    session_store.delete_file("session-local", "folder.json")
    with pytest.raises(FileNotFoundError):
        session_store.delete_file("session-local", "missing.json", missing_ok=False)
    with pytest.raises(OSError):
        session_store.delete_file("session-local", "folder.json", missing_ok=False)

    session_store.delete_file("session-local", "entry.json")
    assert session_store.list_files("session-local") == []


def test_on_disk_deleting_a_namespace_that_is_not_there_makes_nothing(on_disk):
    session_store.delete_file("never-made", "entry.json")

    assert list(on_disk.iterdir()) == []


def test_on_disk_a_namespace_that_cannot_be_removed_is_kept_and_said_so(on_disk, monkeypatch, caplog):
    session_store.write_file("session-local", "entry.json", b"{}")

    def _refused(_path):
        raise OSError("remove refused")

    monkeypatch.setattr(shutil, "rmtree", _refused)
    with caplog.at_level(logging.WARNING, logger=session_store.__name__):
        session_store.delete_session("session-local")

    assert "Failed to remove metadata session" in caplog.text
    assert session_store.list_files("session-local") == ["entry.json"]


def test_on_disk_an_emptied_namespace_is_pruned_unless_an_upload_arrives_meanwhile(on_disk, monkeypatch):
    session_store.ensure_session("emptied")
    session_store.prune_session("emptied")
    assert not (on_disk / "emptied").exists()

    # Another request's upload lands between the marker's removal and the second look.
    session_store.ensure_session("busy")
    delete_file = session_store.delete_file

    def _then_an_upload(session_id, name, **kwargs):
        delete_file(session_id, name, **kwargs)
        session_store.write_file(session_id, "late.json", b"{}")

    monkeypatch.setattr(session_store, "delete_file", _then_an_upload)
    session_store.prune_session("busy")

    assert session_store.list_files("busy") == ["late.json"]


def test_on_disk_an_upload_that_is_not_there_has_no_time(on_disk):
    session_store.write_file("session-local", "entry.json", b"{}")

    assert session_store.file_mtime("session-local", "entry.json") is not None
    assert session_store.file_mtime("session-local", "missing.json") is None


def _refused(*_args, **_kwargs):
    raise fake_gcs.ServiceUnavailable("listing refused")
