"""Additional edge-case contracts for session metadata storage helpers."""

from __future__ import annotations

import os
import types

import pytest


@pytest.fixture
def session_store_local(monkeypatch, tmp_path):
    session_store = pytest.importorskip("server.app.session_metadata_store")

    session_dir = tmp_path / "sessions"
    session_dir.mkdir()

    monkeypatch.setattr(session_store, "SESSION_METADATA_DIR", str(session_dir), raising=False)
    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_local_last_cleanup", 0.0, raising=False)

    return session_store, session_dir


def test_user_root_prefix_rejects_missing_or_blank_session_id(session_store_local):
    session_store, _ = session_store_local

    with pytest.raises(ValueError):
        session_store._user_root_prefix(None)
    with pytest.raises(ValueError):
        session_store._user_root_prefix("   ")


def test_base_prefix_returns_empty_for_blank_folder_prefix(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_USER_FOLDER_PREFIX", "   ", raising=False)

    assert session_store._base_prefix() == ""


def test_normalise_local_session_id_rejects_non_string_values(session_store_local):
    session_store, _ = session_store_local

    with pytest.raises(ValueError):
        session_store._normalise_local_session_id(123)


def test_local_session_directory_returns_none_for_invalid_ids(session_store_local):
    session_store, _ = session_store_local

    assert session_store._local_session_directory("../escape") is None


def test_local_session_directory_logs_and_raises_on_create_failure(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    errors = []
    monkeypatch.setattr(session_store.app.logger, "error", lambda *args, **kwargs: errors.append((args, kwargs)))
    monkeypatch.setattr(
        session_store.os,
        "makedirs",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("mkdir failed")),
    )

    with pytest.raises(OSError, match="mkdir failed"):
        session_store._local_session_directory("session-a", create=True)

    assert errors


def test_local_touch_last_access_swallows_os_errors(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(
        session_store.os,
        "makedirs",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fail")),
    )

    session_store._local_touch_last_access("/tmp/non-existent")


def test_local_resolve_last_access_uses_latest_entry_mtime_when_marker_missing(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    marker_suffix = os.path.join("session-a", session_store._LAST_ACCESS_BLOB)

    def _fake_getmtime(path):
        if path.endswith(marker_suffix):
            raise OSError("missing marker")
        raise OSError("unused")

    class _Entry:
        def __init__(self, mtime):
            self._mtime = mtime

        def stat(self, follow_symlinks=False):
            return types.SimpleNamespace(st_mtime=self._mtime)

    class _Scandir:
        def __enter__(self):
            return iter([_Entry(10.0), _Entry(22.5)])

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(session_store.os.path, "getmtime", _fake_getmtime)
    monkeypatch.setattr(session_store.os, "scandir", lambda _directory: _Scandir())

    assert session_store._local_resolve_last_access("/tmp/session-a") == 22.5


def test_local_resolve_last_access_falls_back_to_directory_mtime(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    marker_suffix = os.path.join("session-a", session_store._LAST_ACCESS_BLOB)

    def _fake_getmtime(path):
        if path.endswith(marker_suffix):
            raise OSError("missing marker")
        return 33.25

    class _Scandir:
        def __enter__(self):
            return iter([])

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(session_store.os.path, "getmtime", _fake_getmtime)
    monkeypatch.setattr(session_store.os, "scandir", lambda _directory: _Scandir())

    assert session_store._local_resolve_last_access("/tmp/session-a") == 33.25


def test_local_resolve_last_access_returns_none_when_scandir_fails(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store.os.path, "getmtime", lambda _path: (_ for _ in ()).throw(OSError("no marker")))
    monkeypatch.setattr(
        session_store.os,
        "scandir",
        lambda _directory: (_ for _ in ()).throw(OSError("cannot scan")),
    )

    assert session_store._local_resolve_last_access("/tmp/session-a") is None


def test_local_cleanup_returns_when_listdir_fails(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(
        session_store.os,
        "listdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cannot list")),
    )

    session_store._local_maybe_cleanup(now=1000.0)


def test_local_cleanup_logs_warning_when_stale_directory_removal_fails(session_store_local, monkeypatch):
    session_store, session_dir = session_store_local

    stale = session_dir / "stale"
    stale.mkdir()
    non_dir = session_dir / "file.txt"
    non_dir.write_text("x", encoding="utf-8")

    monkeypatch.setattr(
        session_store,
        "_local_resolve_last_access",
        lambda directory: 1.0 if directory.endswith("stale") else None,
        raising=False,
    )
    monkeypatch.setattr(
        session_store.shutil,
        "rmtree",
        lambda _path: (_ for _ in ()).throw(OSError("remove failed")),
    )

    warnings = []
    monkeypatch.setattr(session_store.app.logger, "warning", lambda *args, **kwargs: warnings.append((args, kwargs)))

    now = session_store._LOCAL_INACTIVE_AGE.total_seconds() + 1000.0
    session_store._local_maybe_cleanup(now=now)

    assert warnings


def test_local_note_activity_skips_touch_when_directory_missing(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    touched = []
    cleanup = []

    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: "/tmp/missing", raising=False)
    monkeypatch.setattr(session_store.os.path, "isdir", lambda _path: False)
    monkeypatch.setattr(session_store, "_local_touch_last_access", lambda directory: touched.append(directory), raising=False)
    monkeypatch.setattr(session_store, "_local_maybe_cleanup", lambda: cleanup.append(True), raising=False)

    session_store._local_note_activity("session-a")

    assert touched == []
    assert cleanup == [True]


def test_ensure_session_uses_touch_last_access_in_gcs_mode(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    touched = []
    monkeypatch.setattr(session_store, "touch_last_access", lambda sid: touched.append(sid), raising=False)

    session_store.ensure_session("session-a")

    assert touched == ["session-a"]


def test_list_sessions_gcs_extracts_unique_session_ids(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(session_store, "_base_prefix", lambda: "user-data/", raising=False)
    monkeypatch.setattr(
        session_store,
        "list_blob_names",
        lambda _prefix: iter(
            [
                "user-data/session-b/metadata/a.json",
                "user-data/session-a/.last-access",
                "user-data/session-b/metadata/b.json",
                "user-data/",
            ]
        ),
        raising=False,
    )

    assert session_store.list_sessions() == ["session-a", "session-b"]


def test_list_sessions_gcs_logs_and_returns_empty_on_errors(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(
        session_store,
        "list_blob_names",
        lambda _prefix: (_ for _ in ()).throw(RuntimeError("boom")),
        raising=False,
    )

    warnings = []
    monkeypatch.setattr(session_store.app.logger, "warning", lambda *args, **kwargs: warnings.append((args, kwargs)))

    assert session_store.list_sessions() == []
    assert warnings


def test_list_sessions_local_returns_empty_when_directory_unreadable(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(
        session_store.os,
        "listdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cannot list")),
    )

    assert session_store.list_sessions() == []


def test_touch_last_access_local_returns_when_session_directory_invalid(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_local_session_directory", lambda *_args, **_kwargs: None, raising=False)

    session_store.touch_last_access("../invalid")


def test_touch_last_access_local_with_timestamp_swallows_oserror(session_store_local, monkeypatch):
    session_store, session_dir = session_store_local

    directory = str(session_dir / "session-a")
    monkeypatch.setattr(session_store, "_local_session_directory", lambda *_args, **_kwargs: directory, raising=False)
    monkeypatch.setattr(
        session_store.os,
        "makedirs",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("mkdir fail")),
    )

    session_store.touch_last_access("session-a", timestamp=123.0)


def test_resolve_last_access_gcs_falls_back_when_timestamp_is_not_numeric(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(session_store, "download_bytes", lambda _blob: b'{"timestamp":"bad"}', raising=False)
    monkeypatch.setattr(session_store, "blob_updated_timestamp", lambda _blob: 7.5, raising=False)

    assert session_store.resolve_last_access("session-a") == 7.5


def test_list_files_gcs_handles_empty_prefix_and_filters_entries(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(session_store, "_metadata_prefix", lambda _sid: "", raising=False)
    monkeypatch.setattr(
        session_store,
        "list_blob_names",
        lambda _prefix: iter(["entry.json", ".last-access", "nested/"]),
        raising=False,
    )

    assert session_store.list_files("session-a") == ["entry.json"]


def test_list_files_local_handles_invalid_directory_and_os_errors(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: None, raising=False)
    assert session_store.list_files("session-a") == []

    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: "/tmp/session-a", raising=False)
    monkeypatch.setattr(
        session_store.os,
        "listdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cannot list")),
    )
    assert session_store.list_files("session-a") == []


def test_list_files_local_filters_non_files(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: "/tmp/session-a", raising=False)
    monkeypatch.setattr(session_store.os, "listdir", lambda _path: ["entry.json", "nested"]) 
    monkeypatch.setattr(session_store.os.path, "isfile", lambda path: path.endswith("entry.json"))

    assert session_store.list_files("session-a") == ["entry.json"]


def test_read_file_handles_gcs_and_local_error_paths(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(session_store, "download_bytes", lambda _blob: b"payload", raising=False)
    assert session_store.read_file("session-a", "entry.json") == b"payload"

    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: None, raising=False)
    assert session_store.read_file("session-a", "entry.json") is None

    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: "/tmp/session-a", raising=False)

    def _failing_open(*_args, **_kwargs):
        raise OSError("cannot read")

    monkeypatch.setattr("builtins.open", _failing_open)
    assert session_store.read_file("session-a", "entry.json") is None


def test_write_file_local_raises_for_invalid_session_directory(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_local_session_directory", lambda *_args, **_kwargs: None, raising=False)

    with pytest.raises(ValueError, match="Invalid session identifier"):
        session_store.write_file("session-a", "entry.json", b"{}")


def test_delete_file_gcs_updates_last_access(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)

    deleted = []
    touched = []

    monkeypatch.setattr(
        session_store,
        "delete_blob",
        lambda blob_name, *, missing_ok=True: deleted.append((blob_name, missing_ok)),
        raising=False,
    )
    monkeypatch.setattr(session_store, "touch_last_access", lambda sid: touched.append(sid), raising=False)

    session_store.delete_file("session-a", "entry.json", missing_ok=False)

    assert deleted and deleted[0][1] is False
    assert touched == ["session-a"]


def test_delete_file_local_handles_invalid_directory_and_raises_when_requested(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: None, raising=False)
    session_store.delete_file("session-a", "entry.json")

    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: "/tmp/session-a", raising=False)

    monkeypatch.setattr(
        session_store.os,
        "remove",
        lambda _path: (_ for _ in ()).throw(FileNotFoundError("missing")),
    )
    with pytest.raises(FileNotFoundError):
        session_store.delete_file("session-a", "entry.json", missing_ok=False)

    monkeypatch.setattr(
        session_store.os,
        "remove",
        lambda _path: (_ for _ in ()).throw(OSError("blocked")),
    )
    with pytest.raises(OSError):
        session_store.delete_file("session-a", "entry.json", missing_ok=False)


def test_file_mtime_handles_gcs_and_local_failure_paths(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(session_store, "blob_updated_timestamp", lambda _blob: 123.5, raising=False)
    assert session_store.file_mtime("session-a", "entry.json") == 123.5

    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: None, raising=False)
    assert session_store.file_mtime("session-a", "entry.json") is None

    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: "/tmp/session-a", raising=False)
    monkeypatch.setattr(
        session_store.os.path,
        "getmtime",
        lambda _path: (_ for _ in ()).throw(OSError("missing")),
    )
    assert session_store.file_mtime("session-a", "entry.json") is None


def test_delete_session_handles_gcs_empty_prefix_and_local_invalid_directory(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(session_store, "_user_root_prefix", lambda _sid: "", raising=False)
    monkeypatch.setattr(session_store, "list_blob_names", lambda _prefix: iter(["a", "b"]), raising=False)

    deleted = []
    monkeypatch.setattr(
        session_store,
        "delete_blob",
        lambda blob_name, *, missing_ok=True: deleted.append((blob_name, missing_ok)),
        raising=False,
    )

    session_store.delete_session("session-a")
    assert deleted == [("a", True), ("b", True)]

    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: None, raising=False)

    session_store.delete_session("session-a")


def test_prune_session_second_check_can_skip_delete(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    emptiness = iter([True, False])
    monkeypatch.setattr(session_store, "session_is_empty", lambda _sid: next(emptiness), raising=False)

    deleted_files = []
    deleted_sessions = []

    monkeypatch.setattr(
        session_store,
        "delete_file",
        lambda sid, name, *, missing_ok=True: deleted_files.append((sid, name, missing_ok)),
        raising=False,
    )
    monkeypatch.setattr(session_store, "delete_session", lambda sid: deleted_sessions.append(sid), raising=False)

    session_store.prune_session("session-a")

    assert deleted_files == [("session-a", session_store._LAST_ACCESS_BLOB, True)]
    assert deleted_sessions == []


def test_file_exists_returns_false_for_invalid_local_directory(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: None, raising=False)

    assert session_store.file_exists("session-a", "entry.json") is False


def test_local_resolve_last_access_skips_entries_with_stat_errors_and_returns_none_when_directory_mtime_fails(
    session_store_local,
    monkeypatch,
):
    session_store, _ = session_store_local

    marker_suffix = os.path.join("session-a", session_store._LAST_ACCESS_BLOB)

    def _fake_getmtime(path):
        if path.endswith(marker_suffix):
            raise OSError("missing marker")
        raise OSError("missing directory mtime")

    class _BadEntry:
        def stat(self, follow_symlinks=False):
            raise OSError("broken stat")

    class _Scandir:
        def __enter__(self):
            return iter([_BadEntry()])

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(session_store.os.path, "getmtime", _fake_getmtime)
    monkeypatch.setattr(session_store.os, "scandir", lambda _directory: _Scandir())

    assert session_store._local_resolve_last_access("/tmp/session-a") is None


def test_local_cleanup_handles_listdir_oserror_after_interval_elapsed(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(
        session_store.os,
        "listdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cannot list")),
    )

    now = session_store._LOCAL_CLEANUP_INTERVAL.total_seconds() + 1.0
    session_store._local_maybe_cleanup(now=now)


def test_list_sessions_gcs_skips_empty_session_components(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(session_store, "_base_prefix", lambda: "user-data/", raising=False)
    monkeypatch.setattr(
        session_store,
        "list_blob_names",
        lambda _prefix: iter(["user-data//metadata/a.json", "user-data/session-a/metadata/b.json"]),
        raising=False,
    )

    assert session_store.list_sessions() == ["session-a"]


def test_list_sessions_local_skips_hidden_and_non_directory_entries(session_store_local):
    session_store, session_dir = session_store_local

    (session_dir / ".hidden").mkdir()
    (session_dir / "regular-file.txt").write_text("x", encoding="utf-8")

    assert session_store.list_sessions() == []


def test_resolve_last_access_gcs_falls_back_when_marker_payload_missing(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(session_store, "download_bytes", lambda _blob: None, raising=False)
    monkeypatch.setattr(session_store, "blob_updated_timestamp", lambda _blob: 42.0, raising=False)

    assert session_store.resolve_last_access("session-a") == 42.0


def test_resolve_last_access_local_returns_none_for_invalid_session(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: None, raising=False)

    assert session_store.resolve_last_access("../invalid") is None


def test_list_files_gcs_skips_empty_remainders(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(session_store, "_metadata_prefix", lambda _sid: "meta", raising=False)
    monkeypatch.setattr(session_store, "list_blob_names", lambda _prefix: iter(["meta/"]), raising=False)

    assert session_store.list_files("session-a") == []


def test_delete_file_local_swallows_errors_when_missing_ok_true(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "_local_session_directory", lambda _sid: "/tmp/session-a", raising=False)
    monkeypatch.setattr(
        session_store.os,
        "remove",
        lambda _path: (_ for _ in ()).throw(FileNotFoundError("missing")),
    )
    session_store.delete_file("session-a", "entry.json", missing_ok=True)

    monkeypatch.setattr(
        session_store.os,
        "remove",
        lambda _path: (_ for _ in ()).throw(OSError("blocked")),
    )
    session_store.delete_file("session-a", "entry.json", missing_ok=True)


def test_session_is_empty_reflects_list_files_results(session_store_local, monkeypatch):
    session_store, _ = session_store_local

    monkeypatch.setattr(session_store, "list_files", lambda _sid: [], raising=False)
    assert session_store.session_is_empty("session-a") is True

    monkeypatch.setattr(session_store, "list_files", lambda _sid: ["entry.json"], raising=False)
    assert session_store.session_is_empty("session-a") is False


def test_local_resolve_last_access_keeps_existing_latest_when_next_candidate_is_older(
    session_store_local,
    monkeypatch,
):
    session_store, _ = session_store_local

    marker_suffix = os.path.join("session-a", session_store._LAST_ACCESS_BLOB)

    def _fake_getmtime(path):
        if path.endswith(marker_suffix):
            raise OSError("missing marker")
        raise OSError("unused")

    class _Entry:
        def __init__(self, mtime):
            self._mtime = mtime

        def stat(self, follow_symlinks=False):
            return types.SimpleNamespace(st_mtime=self._mtime)

    class _Scandir:
        def __enter__(self):
            return iter([_Entry(50.0), _Entry(20.0)])

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(session_store.os.path, "getmtime", _fake_getmtime)
    monkeypatch.setattr(session_store.os, "scandir", lambda _directory: _Scandir())

    assert session_store._local_resolve_last_access("/tmp/session-a") == 50.0
