import json

import pytest

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import uploads as mds_uploads
from server.app.storage import cloud as storage_cloud
from server.app.storage import common as storage_common
from server.app.storage import session_metadata
from tests.app.entry_app import entry_app


@pytest.fixture
def metadata_local_env(monkeypatch, tmp_path, metadata_state):
    session_dir = tmp_path / "session-metadata"
    session_dir.mkdir()

    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(session_dir))

    monkeypatch.setattr(storage_cloud, "gcs_enabled", lambda: False)
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)


    return entry_app()


def _sample_payload(description: str = "Session entry") -> dict:
    return {
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "metadataStatement": {"description": description},
        "statusReports": [{"status": "NOT_FIDO_CERTIFIED"}],
    }


def test_session_metadata_item_lifecycle_save_list_serialize_delete(metadata_local_env):
    app = metadata_local_env

    with app.test_request_context("/"):
        visitor_session.ensure_id()
        saved = mds_uploads.save_session_metadata_item(
            _sample_payload("Lifecycle test"),
            original_filename="custom.json",
        )

        assert saved.filename.endswith(".json")
        assert saved.original_filename == "custom.json"

        listed = mds_uploads.list_session_metadata_items()
        assert len(listed) == 1
        assert listed[0].payload["metadataStatement"]["description"] == "Lifecycle test"

        serialized = mds_uploads.serialize_session_metadata_item(listed[0])
        assert serialized["source"]["storedFilename"] == listed[0].filename
        assert serialized["source"]["originalFilename"] == "custom.json"

        assert mds_uploads.delete_session_metadata_item(listed[0].filename) is True
        assert mds_uploads.list_session_metadata_items() == []


def test_save_session_metadata_item_surfaces_storage_failures(metadata_local_env, monkeypatch):
    app = metadata_local_env

    calls = []

    def _failing_write(*_args, **_kwargs):
        calls.append("write")
        raise OSError("disk full")

    monkeypatch.setattr(session_metadata, "write_file", _failing_write)

    with app.test_request_context("/"):
        visitor_session.ensure_id()
        with pytest.raises(RuntimeError, match="Failed to store uploaded metadata"):
            mds_uploads.save_session_metadata_item(_sample_payload("broken"))

    assert calls == ["write"]


def test_list_session_metadata_items_skips_invalid_payloads_and_returns_valid_entries(metadata_local_env):
    app = metadata_local_env

    with app.test_request_context("/"):
        session_id = visitor_session.ensure_id()
        directory = mds_uploads._session_metadata_directory(session_id, create=True)

        session_metadata.write_file(
            directory,
            "valid.json",
            (json.dumps(_sample_payload("valid")) + "\n").encode("utf-8"),
            content_type="application/json",
        )
        session_metadata.write_file(
            directory,
            "invalid.json",
            b"not-json",
            content_type="application/json",
        )
        session_metadata.write_file(
            directory,
            "broken.json",
            b"[]",
            content_type="application/json",
        )

        items = mds_uploads.list_session_metadata_items()

    assert len(items) == 1
    assert items[0].payload["metadataStatement"]["description"] == "valid"


def test_delete_session_metadata_item_validates_session_filename_and_storage_errors(metadata_local_env, monkeypatch):
    app = metadata_local_env

    assert mds_uploads.delete_session_metadata_item("entry.json", session_id=None) is False

    with app.test_request_context("/"):
        session_id = visitor_session.ensure_id()

        with pytest.raises(ValueError, match="Invalid metadata filename"):
            mds_uploads.delete_session_metadata_item("../evil.json", session_id=session_id)

        assert mds_uploads.delete_session_metadata_item("missing.json", session_id=session_id) is False

        directory = mds_uploads._session_metadata_directory(session_id, create=True)
        session_metadata.write_file(directory, "present.json", b"{}", content_type="application/json")

        monkeypatch.setattr(
            session_metadata,
            "delete_file",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cannot delete")),
        )

        with pytest.raises(RuntimeError, match="Failed to delete"):
            mds_uploads.delete_session_metadata_item("present.json", session_id=session_id)


def test_load_verified_metadata_helpers_handle_invalid_and_missing_payloads(metadata_local_env, monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))
    verified_path = tmp_path / "fido-mds3.verified.json"

    assert mds_cache._load_verified_metadata_payload() is None

    verified_path.write_text("[]", encoding="utf-8")
    assert mds_cache._load_verified_metadata_payload() is None

    verified_path.write_text("{\"broken\": true}", encoding="utf-8")
    loaded, mtime = mds_cache._load_verified_metadata_fallback()
    assert loaded is None
    assert mtime is not None
