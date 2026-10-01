from types import SimpleNamespace

import pytest
from flask import session as flask_session

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import effective as mds_effective
from server.app.mds import uploads as mds_uploads
from server.app.storage import cloud as storage_cloud
from server.app.storage import common as storage_common
from tests.app.entry_app import entry_app


@pytest.fixture
def session_metadata_env(monkeypatch, tmp_path, metadata_state):
    session_dir = tmp_path / "sessions"
    session_dir.mkdir()

    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(session_dir))

    monkeypatch.setattr(storage_cloud, "gcs_enabled", lambda: False)
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)


    return entry_app()


def _sample_entry(description: str) -> dict:
    return {
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "metadataStatement": {
            "description": description,
        },
    }


def test_session_metadata_is_isolated(session_metadata_env):
    app = session_metadata_env

    with app.test_request_context("/"):
        first_session_id = visitor_session.ensure_id()
        mds_uploads.save_session_metadata_item(_sample_entry("Session entry"))
        items_for_first = mds_uploads.list_session_metadata_items()
        assert len(items_for_first) == 1

    with app.test_request_context("/"):
        assert mds_uploads.list_session_metadata_items() == []
        second_session_id = visitor_session.ensure_id()
        assert second_session_id != first_session_id
        assert mds_uploads.list_session_metadata_items() == []

    with app.test_request_context("/"):
        flask_session[visitor_session.SESSION_KEY] = first_session_id
        items = mds_uploads.list_session_metadata_items()
        assert len(items) == 1
        assert items[0].payload["metadataStatement"]["description"] == "Session entry"


def test_note_session_activity_schedules_cleanup(session_metadata_env, monkeypatch):
    calls = []
    monkeypatch.setattr(visitor_session, "_touch_last_access", lambda sid: calls.append(("touch", sid)))
    monkeypatch.setattr(visitor_session, "schedule_cleanup", lambda: calls.append(("schedule", None)))
    monkeypatch.setattr(
        visitor_session,
        "_maybe_cleanup",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("inline cleanup should not run")),
    )

    visitor_session.note_activity("session-123")

    assert calls == [("touch", "session-123"), ("schedule", None)]


def test_resolve_effective_metadata_entry_accepts_hyphenated_aaguid(monkeypatch):
    base_entry = {
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "metadataStatement": {
            "description": "Packaged authenticator",
            "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        },
        "statusReports": [],
    }

    monkeypatch.setattr(mds_uploads, "list_session_metadata_items", lambda: [])
    monkeypatch.setattr(
        mds_cache,
        "load_packaged_explorer_summary",
        lambda: {"generatedAt": "2026-04-02T00:00:00+00:00", "no": 1},
    )
    monkeypatch.setattr(
        mds_cache,
        "_load_base_metadata",
        lambda: (SimpleNamespace(entries=[base_entry]), "packaged"),
    )

    resolved = mds_effective.resolve_effective_metadata_entry(
        aaguid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    )

    assert resolved is not None
    assert resolved["entryId"] == "aaguid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert resolved["metadataStatement"]["description"] == "Packaged authenticator"


def test_load_effective_full_snapshot_prefers_session_entry(monkeypatch):
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

    session_item = mds_uploads.SessionMetadataItem(
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

    monkeypatch.setattr(mds_cache, "_load_base_full_snapshot", lambda: (base_snapshot, 1.0))
    monkeypatch.setattr(mds_uploads, "list_session_metadata_items", lambda: [session_item])

    snapshot = mds_effective.load_effective_full_snapshot()

    assert snapshot["meta"]["entryCount"] == 1
    assert snapshot["meta"]["customEntryCount"] == 1
    assert snapshot["entries"][0]["source"] == "session"
    assert snapshot["entries"][0]["metadataStatement"]["description"] == "Session authenticator"
