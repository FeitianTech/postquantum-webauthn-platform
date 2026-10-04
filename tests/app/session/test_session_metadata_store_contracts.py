from pathlib import Path

import pytest

from server.app import visitor_session
from server.app.storage import common as storage_common
from server.app.storage import session_metadata as session_store
from tests.app.storage import fake_gcs


@pytest.fixture
def session_metadata_dir(monkeypatch, tmp_path):
    session_dir = tmp_path / "session-metadata"
    session_dir.mkdir()

    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(session_dir))

    return session_dir


def test_local_write_read_list_delete_roundtrip(session_metadata_dir, monkeypatch):
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)

    session_store.write_file("session-local", "entry.json", b"{\"ok\":true}")

    assert session_store.file_exists("session-local", "entry.json") is True
    assert session_store.list_files("session-local") == ["entry.json"]
    assert session_store.read_file("session-local", "entry.json") == b"{\"ok\":true}"
    assert session_store.file_mtime("session-local", "entry.json") is not None

    session_store.delete_file("session-local", "entry.json")

    assert session_store.file_exists("session-local", "entry.json") is False
    assert session_store.list_files("session-local") == []


def test_local_touch_last_access_with_explicit_timestamp(session_metadata_dir, monkeypatch):
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)

    expected_timestamp = 1_700_000_123.0
    session_store.touch_last_access("session-touch", timestamp=expected_timestamp)

    resolved_timestamp = session_store.resolve_last_access("session-touch")
    assert resolved_timestamp is not None
    assert abs(resolved_timestamp - expected_timestamp) < 1.0


def test_local_cleanup_removes_only_stale_non_hidden_sessions(session_metadata_dir, monkeypatch):
    session_dir = session_metadata_dir
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)
    monkeypatch.setattr(visitor_session, "CLEANUP", visitor_session.CleanupState())

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
    )

    visitor_session._maybe_cleanup(now=now)

    assert stale_dir.exists() is False
    assert fresh_dir.exists() is True
    assert hidden_dir.exists() is True


def test_local_cleanup_respects_cleanup_interval_guard(session_metadata_dir, monkeypatch):
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)
    monkeypatch.setattr(visitor_session, "CLEANUP", visitor_session.CleanupState(last_run=2_000.0))

    monkeypatch.setattr(
        session_store.os,
        "listdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("listdir should not run")),
    )

    visitor_session._maybe_cleanup(now=2_500.0)


def test_deleting_the_last_upload_keeps_the_namespaces_other_stores_on_cloud_storage(monkeypatch):
    bucket = fake_gcs.install(monkeypatch, "every store")
    credentials = storage_common.session_prefix("session-gcs", "credentials") + "/user@example.com_credential_data.json"
    artifact = storage_common.session_prefix("session-gcs", "credential-artifacts") + "/stored.json"
    bucket.put(credentials, b"{}")
    bucket.put(artifact, b"{}")
    session_store.touch_last_access("session-gcs")
    session_store.write_file("session-gcs", "entry.json", b"{}")

    session_store.delete_file("session-gcs", "entry.json")
    session_store.prune_session("session-gcs")

    assert session_store.list_files("session-gcs") == []
    assert credentials in bucket.objects
    assert artifact in bucket.objects
    assert session_store.resolve_last_access("session-gcs") is not None


def test_a_local_folder_that_cannot_be_listed_is_not_pruned(session_metadata_dir, monkeypatch):
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)
    (session_metadata_dir / "session-local").write_text("not a folder")

    with pytest.raises(storage_common.StorageReadError):
        session_store.prune_session("session-local")
    assert (session_metadata_dir / "session-local").read_text() == "not a folder"
