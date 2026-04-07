import json
from pathlib import Path

import pytest


@pytest.fixture
def session_store_module(monkeypatch, tmp_path):
    session_store = pytest.importorskip("server.app.session_metadata_store")

    session_dir = tmp_path / "session-metadata"
    session_dir.mkdir()

    monkeypatch.setattr(session_store, "SESSION_METADATA_DIR", str(session_dir), raising=False)
    monkeypatch.setattr(session_store, "_local_last_cleanup", 0.0, raising=False)

    return session_store, session_dir


def test_local_write_read_list_delete_roundtrip(session_store_module, monkeypatch):
    session_store, _ = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)

    session_store.write_file("session-local", "entry.json", b"{\"ok\":true}")

    assert session_store.file_exists("session-local", "entry.json") is True
    assert session_store.list_files("session-local") == ["entry.json"]
    assert session_store.read_file("session-local", "entry.json") == b"{\"ok\":true}"
    assert session_store.file_mtime("session-local", "entry.json") is not None

    session_store.delete_file("session-local", "entry.json")

    assert session_store.file_exists("session-local", "entry.json") is False
    assert session_store.list_files("session-local") == []


def test_local_touch_last_access_with_explicit_timestamp(session_store_module, monkeypatch):
    session_store, _ = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)

    expected_timestamp = 1_700_000_123.0
    session_store.touch_last_access("session-touch", timestamp=expected_timestamp)

    resolved_timestamp = session_store.resolve_last_access("session-touch")
    assert resolved_timestamp is not None
    assert abs(resolved_timestamp - expected_timestamp) < 1.0


def test_local_cleanup_removes_only_stale_non_hidden_sessions(session_store_module, monkeypatch):
    session_store, session_dir = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)

    stale_dir = session_dir / "stale-session"
    fresh_dir = session_dir / "fresh-session"
    hidden_dir = session_dir / ".hidden-session"
    stale_dir.mkdir()
    fresh_dir.mkdir()
    hidden_dir.mkdir()

    now = 2_000_000.0
    last_access = {
        "stale-session": 100.0,
        "fresh-session": now - 10.0,
        ".hidden-session": 0.0,
    }

    monkeypatch.setattr(
        session_store,
        "_local_resolve_last_access",
        lambda directory: last_access.get(Path(directory).name),
        raising=False,
    )

    session_store._local_maybe_cleanup(now=now)

    assert stale_dir.exists() is False
    assert fresh_dir.exists() is True
    assert hidden_dir.exists() is True


def test_local_cleanup_respects_cleanup_interval_guard(session_store_module, monkeypatch):
    session_store, _ = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_local_last_cleanup", 2_000.0, raising=False)

    monkeypatch.setattr(
        session_store.os,
        "listdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("listdir should not run")),
        raising=False,
    )

    session_store._local_maybe_cleanup(now=2_500.0)


def test_gcs_touch_last_access_uploads_json_marker(session_store_module, monkeypatch):
    session_store, _ = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)

    uploads = []
    monkeypatch.setattr(
        session_store,
        "upload_bytes",
        lambda blob_name, data, *, content_type=None: uploads.append((blob_name, data, content_type)),
        raising=False,
    )

    session_store.touch_last_access("session-gcs", timestamp=321.5)

    assert len(uploads) == 1
    blob_name, raw_payload, content_type = uploads[0]
    assert blob_name.endswith("/.last-access")
    assert content_type == "application/json"

    payload = json.loads(raw_payload.decode("utf-8"))
    assert payload["timestamp"] == 321.5


def test_gcs_resolve_last_access_prefers_marker_timestamp(session_store_module, monkeypatch):
    session_store, _ = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)

    monkeypatch.setattr(
        session_store,
        "download_bytes",
        lambda _blob_name: b'{"timestamp": 123.25}',
        raising=False,
    )
    monkeypatch.setattr(session_store, "blob_updated_timestamp", lambda _blob_name: 999.0, raising=False)

    assert session_store.resolve_last_access("session-gcs") == 123.25


def test_gcs_resolve_last_access_falls_back_to_blob_timestamp(session_store_module, monkeypatch):
    session_store, _ = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)

    monkeypatch.setattr(session_store, "download_bytes", lambda _blob_name: b"not-json", raising=False)
    monkeypatch.setattr(session_store, "blob_updated_timestamp", lambda _blob_name: 456.5, raising=False)

    assert session_store.resolve_last_access("session-gcs") == 456.5


def test_gcs_list_files_filters_last_access_and_folder_markers(session_store_module, monkeypatch):
    session_store, _ = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)

    prefix = session_store._metadata_prefix("session-gcs") + "/"
    blob_names = [
        prefix + "b.json",
        prefix + ".last-access",
        prefix + "nested/",
        prefix + "a.json",
    ]

    monkeypatch.setattr(session_store, "list_blob_names", lambda _prefix: blob_names, raising=False)

    assert session_store.list_files("session-gcs") == ["a.json", "b.json"]


def test_gcs_delete_session_deletes_all_session_blobs(session_store_module, monkeypatch):
    session_store, _ = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)

    prefix = session_store._user_root_prefix("session-gcs") + "/"
    blob_names = [
        prefix + "metadata/a.json",
        prefix + "metadata/b.json",
        prefix + ".last-access",
    ]

    monkeypatch.setattr(session_store, "list_blob_names", lambda _prefix: blob_names, raising=False)

    deleted = []
    monkeypatch.setattr(
        session_store,
        "delete_blob",
        lambda blob_name, *, missing_ok=True: deleted.append((blob_name, missing_ok)),
        raising=False,
    )

    session_store.delete_session("session-gcs")

    assert deleted == [(blob_names[0], True), (blob_names[1], True), (blob_names[2], True)]


def test_gcs_write_file_uploads_and_updates_last_access(session_store_module, monkeypatch):
    session_store, _ = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)

    uploads = []
    monkeypatch.setattr(
        session_store,
        "upload_bytes",
        lambda blob_name, data, *, content_type=None: uploads.append((blob_name, data, content_type)),
        raising=False,
    )

    touched = []
    monkeypatch.setattr(session_store, "touch_last_access", lambda sid: touched.append(sid), raising=False)

    session_store.write_file(
        "session-gcs",
        "entry.json",
        b"{}",
        content_type="application/json",
    )

    assert len(uploads) == 1
    blob_name, payload, content_type = uploads[0]
    assert blob_name.endswith("/metadata/entry.json")
    assert payload == b"{}"
    assert content_type == "application/json"
    assert touched == ["session-gcs"]


def test_gcs_file_exists_proxies_blob_exists(session_store_module, monkeypatch):
    session_store, _ = session_store_module
    monkeypatch.setattr(session_store, "_using_gcs", lambda: True, raising=False)

    monkeypatch.setattr(
        session_store,
        "blob_exists",
        lambda blob_name: blob_name.endswith("/metadata/present.json"),
        raising=False,
    )

    assert session_store.file_exists("session-gcs", "present.json") is True
    assert session_store.file_exists("session-gcs", "missing.json") is False
