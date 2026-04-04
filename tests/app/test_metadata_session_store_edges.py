import json

import pytest


@pytest.fixture
def metadata_local_env(monkeypatch, tmp_path):
    metadata = pytest.importorskip("server.app.metadata")
    session_store = pytest.importorskip("server.app.session_metadata_store")
    config = pytest.importorskip("server.app.config")

    session_dir = tmp_path / "session-metadata"
    session_dir.mkdir()

    monkeypatch.setattr(config, "SESSION_METADATA_DIR", str(session_dir), raising=False)
    monkeypatch.setattr(session_store, "SESSION_METADATA_DIR", str(session_dir), raising=False)
    monkeypatch.setattr(metadata, "SESSION_METADATA_DIR", str(session_dir), raising=False)

    monkeypatch.setattr(session_store, "gcs_enabled", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)

    monkeypatch.setattr(metadata, "_session_metadata_entry_ids", set(), raising=False)
    monkeypatch.setattr(metadata, "_session_metadata_last_cleanup", 0.0, raising=False)

    return metadata, session_store, config.app


def _sample_payload(description: str = "Session entry") -> dict:
    return {
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "metadataStatement": {"description": description},
        "statusReports": [{"status": "NOT_FIDO_CERTIFIED"}],
    }


def test_session_metadata_item_lifecycle_save_list_serialize_delete(metadata_local_env):
    metadata, _session_store, app = metadata_local_env

    with app.test_request_context("/"):
        metadata.ensure_metadata_session_id()
        saved = metadata.save_session_metadata_item(
            _sample_payload("Lifecycle test"),
            original_filename="custom.json",
        )

        assert saved.filename.endswith(".json")
        assert saved.original_filename == "custom.json"

        listed = metadata.list_session_metadata_items()
        assert len(listed) == 1
        assert listed[0].payload["metadataStatement"]["description"] == "Lifecycle test"

        serialized = metadata.serialize_session_metadata_item(listed[0])
        assert serialized["source"]["storedFilename"] == listed[0].filename
        assert serialized["source"]["originalFilename"] == "custom.json"

        assert metadata.delete_session_metadata_item(listed[0].filename) is True
        assert metadata.list_session_metadata_items() == []


def test_save_session_metadata_item_surfaces_storage_failures(metadata_local_env, monkeypatch):
    metadata, session_store, app = metadata_local_env

    calls = []

    def _failing_write(*_args, **_kwargs):
        calls.append("write")
        raise OSError("disk full")

    monkeypatch.setattr(session_store, "write_file", _failing_write, raising=False)

    with app.test_request_context("/"):
        metadata.ensure_metadata_session_id()
        with pytest.raises(RuntimeError, match="Failed to store uploaded metadata"):
            metadata.save_session_metadata_item(_sample_payload("broken"))

    assert calls == ["write"]


def test_list_session_metadata_items_skips_invalid_payloads_and_returns_valid_entries(
    metadata_local_env,
):
    metadata, session_store, app = metadata_local_env

    with app.test_request_context("/"):
        session_id = metadata.ensure_metadata_session_id()
        directory = metadata._session_metadata_directory(session_id, create=True)

        session_store.write_file(
            directory,
            "valid.json",
            (json.dumps(_sample_payload("valid")) + "\n").encode("utf-8"),
            content_type="application/json",
        )
        session_store.write_file(
            directory,
            "invalid.json",
            b"not-json",
            content_type="application/json",
        )
        session_store.write_file(
            directory,
            "broken.json",
            b"[]",
            content_type="application/json",
        )

        items = metadata.list_session_metadata_items()

    assert len(items) == 1
    assert items[0].payload["metadataStatement"]["description"] == "valid"


def test_delete_session_metadata_item_validates_session_filename_and_storage_errors(
    metadata_local_env, monkeypatch
):
    metadata, session_store, app = metadata_local_env

    with pytest.raises(ValueError, match="No active metadata session"):
        metadata.delete_session_metadata_item("entry.json", session_id=None)

    with app.test_request_context("/"):
        session_id = metadata.ensure_metadata_session_id()

        with pytest.raises(ValueError, match="Invalid metadata filename"):
            metadata.delete_session_metadata_item("../evil.json", session_id=session_id)

        assert metadata.delete_session_metadata_item("missing.json", session_id=session_id) is False

        directory = metadata._session_metadata_directory(session_id, create=True)
        session_store.write_file(directory, "present.json", b"{}", content_type="application/json")

        monkeypatch.setattr(
            session_store,
            "delete_file",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cannot delete")),
            raising=False,
        )

        with pytest.raises(RuntimeError, match="Failed to delete"):
            metadata.delete_session_metadata_item("present.json", session_id=session_id)


def test_load_verified_metadata_helpers_handle_invalid_and_missing_payloads(metadata_local_env, monkeypatch, tmp_path):
    metadata, _session_store, _app = metadata_local_env

    verified_path = tmp_path / "verified.json"
    monkeypatch.setattr(metadata, "MDS_METADATA_VERIFIED_PATH", str(verified_path), raising=False)

    assert metadata._load_verified_metadata_payload() is None

    verified_path.write_text("[]", encoding="utf-8")
    assert metadata._load_verified_metadata_payload() is None

    verified_path.write_text("{\"broken\": true}", encoding="utf-8")
    loaded, mtime = metadata._load_verified_metadata_fallback()
    assert loaded is None
    assert mtime is not None
