import pytest
from flask import session as flask_session
from types import SimpleNamespace


@pytest.fixture
def session_metadata_env(monkeypatch, tmp_path):
    config = pytest.importorskip("server.app.config")
    metadata = pytest.importorskip("server.app.metadata")
    session_store = pytest.importorskip("server.app.session_metadata_store")

    session_dir = tmp_path / "sessions"
    session_dir.mkdir()

    monkeypatch.setattr(config, "SESSION_METADATA_DIR", str(session_dir), raising=False)
    monkeypatch.setattr(metadata, "SESSION_METADATA_DIR", str(session_dir), raising=False)
    monkeypatch.setattr(session_store, "SESSION_METADATA_DIR", str(session_dir), raising=False)

    monkeypatch.setattr(session_store, "gcs_enabled", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_local_last_cleanup", 0.0, raising=False)

    monkeypatch.setattr(metadata, "_session_metadata_entry_ids", set(), raising=False)
    monkeypatch.setattr(metadata, "_session_metadata_last_cleanup", 0.0, raising=False)

    return config.app, metadata


def _sample_entry(description: str) -> dict:
    return {
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "metadataStatement": {
            "description": description,
        },
    }


def test_session_metadata_is_isolated(session_metadata_env):
    app, metadata = session_metadata_env

    with app.test_request_context("/"):
        first_session_id = metadata.ensure_metadata_session_id()
        metadata.save_session_metadata_item(_sample_entry("Session entry"))
        items_for_first = metadata.list_session_metadata_items()
        assert len(items_for_first) == 1

    with app.test_request_context("/"):
        assert metadata.list_session_metadata_items() == []
        second_session_id = metadata.ensure_metadata_session_id()
        assert second_session_id != first_session_id
        assert metadata.list_session_metadata_items() == []

    with app.test_request_context("/"):
        flask_session[metadata._SESSION_METADATA_SESSION_KEY] = first_session_id
        items = metadata.list_session_metadata_items()
        assert len(items) == 1
        assert items[0].payload["metadataStatement"]["description"] == "Session entry"


def test_runtime_metadata_download_disabled():
    metadata = pytest.importorskip("server.app.metadata")
    with pytest.raises(RuntimeError):
        metadata.download_metadata_blob()


def test_note_session_activity_schedules_cleanup(session_metadata_env, monkeypatch):
    _, metadata = session_metadata_env

    calls = []
    monkeypatch.setattr(metadata, "_touch_session_last_access", lambda sid: calls.append(("touch", sid)))
    monkeypatch.setattr(metadata, "_schedule_inactive_session_cleanup", lambda: calls.append(("schedule", None)))
    monkeypatch.setattr(
        metadata,
        "_maybe_cleanup_inactive_sessions",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("inline cleanup should not run")),
    )

    metadata._note_session_activity("session-123")

    assert calls == [("touch", "session-123"), ("schedule", None)]


def test_resolve_effective_metadata_entry_accepts_hyphenated_aaguid(monkeypatch):
    metadata = pytest.importorskip("server.app.metadata")

    base_entry = {
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "metadataStatement": {
            "description": "Packaged authenticator",
            "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        },
        "statusReports": [],
    }

    monkeypatch.setattr(metadata, "list_session_metadata_items", lambda: [], raising=False)
    monkeypatch.setattr(
        metadata,
        "load_packaged_explorer_summary",
        lambda: {"generatedAt": "2026-04-02T00:00:00+00:00", "no": 1},
        raising=False,
    )
    monkeypatch.setattr(
        metadata,
        "_load_base_metadata",
        lambda: (SimpleNamespace(entries=[base_entry]), "packaged"),
        raising=False,
    )

    resolved = metadata.resolve_effective_metadata_entry(
        aaguid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    )

    assert resolved is not None
    assert resolved["entryId"] == "aaguid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert resolved["metadataStatement"]["description"] == "Packaged authenticator"


def test_load_effective_full_snapshot_prefers_session_entry(monkeypatch):
    metadata = pytest.importorskip("server.app.metadata")

    base_snapshot = {
        "meta": {"entryCount": 1, "source": "packaged"},
        "entries": [
            {
                "entryId": "aaguid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "name": "Packaged authenticator",
                "metadataStatement": {"description": "Packaged authenticator"},
                "statusReports": [],
                "isLightweightEntry": False,
            }
        ],
    }

    session_item = metadata.SessionMetadataItem(
        filename="custom.json",
        payload={
            "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "metadataStatement": {
                "description": "Session authenticator",
                "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            },
            "statusReports": [],
        },
        legal_header=None,
        entry=None,
        uploaded_at="2026-04-02T00:00:00+00:00",
        original_filename="custom.json",
        mtime=None,
    )

    monkeypatch.setattr(metadata, "_load_base_full_snapshot", lambda: (base_snapshot, 1.0), raising=False)
    monkeypatch.setattr(metadata, "list_session_metadata_items", lambda: [session_item], raising=False)

    snapshot = metadata.load_effective_full_snapshot()

    assert snapshot["meta"]["entryCount"] == 1
    assert snapshot["meta"]["customEntryCount"] == 1
    assert snapshot["entries"][0]["source"] == "session"
    assert snapshot["entries"][0]["metadataStatement"]["description"] == "Session authenticator"
