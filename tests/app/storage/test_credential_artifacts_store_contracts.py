import os

import pytest


@pytest.fixture
def artifact_module(monkeypatch, tmp_path):
    module = pytest.importorskip("server.app.credential_artifacts")
    monkeypatch.setattr(module, "_ARTIFACT_DIR", str(tmp_path), raising=False)
    monkeypatch.setattr(module, "_using_gcs", lambda: False, raising=False)
    return module


def test_store_load_delete_credential_artifact_round_trip_local(artifact_module):
    payload = {
        "storedCredential": {
            "credentialId": "cred-1",
            "signCount": 4,
        }
    }

    stored = artifact_module.store_credential_artifact(
        "cred-1",
        payload,
        session_id="session-a",
    )
    assert stored is True

    loaded = artifact_module.load_credential_artifact("cred-1", session_id="session-a")
    assert loaded == payload

    deleted = artifact_module.delete_credential_artifact("cred-1", session_id="session-a")
    assert deleted is True

    assert artifact_module.load_credential_artifact("cred-1", session_id="session-a") is None


def test_store_credential_artifact_rejects_invalid_inputs(artifact_module):
    assert (
        artifact_module.store_credential_artifact("   ", {"x": 1}, session_id="session-a")
        is False
    )
    assert (
        artifact_module.store_credential_artifact(None, {"x": 1}, session_id="session-a")
        is False
    )
    assert (
        artifact_module.store_credential_artifact("cred-1", "not-a-dict", session_id="session-a")
        is False
    )


def test_store_credential_artifact_merge_recursively_updates_nested_payload(artifact_module):
    initial_payload = {
        "storedCredential": {
            "credentialId": "cred-merge",
            "properties": {
                "signCount": 4,
                "flags": {"uv": False, "up": True},
            },
        }
    }
    update_payload = {
        "storedCredential": {
            "properties": {
                "signCount": 5,
                "flags": {"uv": True},
            },
            "aaguid": "00112233",
        }
    }

    assert artifact_module.store_credential_artifact(
        "cred-merge",
        initial_payload,
        session_id="session-a",
    )
    assert artifact_module.store_credential_artifact(
        "cred-merge",
        update_payload,
        merge=True,
        session_id="session-a",
    )

    loaded = artifact_module.load_credential_artifact("cred-merge", session_id="session-a")
    assert loaded == {
        "storedCredential": {
            "credentialId": "cred-merge",
            "properties": {
                "signCount": 5,
                "flags": {"uv": True, "up": True},
            },
            "aaguid": "00112233",
        }
    }


def test_store_credential_artifact_merge_preserves_created_at_and_updates_updated_at(
    artifact_module, monkeypatch
):
    time_values = iter([100.0, 250.0])
    monkeypatch.setattr(artifact_module.time, "time", lambda: next(time_values), raising=False)

    assert artifact_module.store_credential_artifact(
        "cred-time",
        {"v": 1},
        session_id="session-a",
    )

    first_record = artifact_module._read_record("cred-time", "session-a")
    assert isinstance(first_record, dict)
    assert first_record["createdAt"] == 100.0
    assert first_record["updatedAt"] == 100.0

    assert artifact_module.store_credential_artifact(
        "cred-time",
        {"v": 2},
        merge=True,
        session_id="session-a",
    )

    second_record = artifact_module._read_record("cred-time", "session-a")
    assert isinstance(second_record, dict)
    assert second_record["createdAt"] == 100.0
    assert second_record["updatedAt"] == 250.0


def test_load_credential_artifact_returns_none_for_corrupt_json_local(artifact_module):
    os.makedirs(artifact_module._ARTIFACT_DIR, exist_ok=True)
    path = artifact_module._artifact_path("cred-corrupt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("{broken-json")

    assert artifact_module.load_credential_artifact("cred-corrupt", session_id="session-a") is None


def test_delete_credential_artifact_returns_false_when_missing(artifact_module):
    assert artifact_module.delete_credential_artifact("missing", session_id="session-a") is False


def test_artifact_blob_is_session_scoped(artifact_module):
    first_blob = artifact_module._artifact_blob("cred-blob", "session-a")
    second_blob = artifact_module._artifact_blob("cred-blob", "session-b")

    assert first_blob != second_blob
    assert "session-a" in first_blob
    assert "session-b" in second_blob


def test_resolve_session_id_prefers_explicit_value(artifact_module):
    resolved = artifact_module._resolve_session_id(" explicit-session ")
    assert resolved == "explicit-session"


def test_resolve_session_id_falls_back_to_metadata_session(monkeypatch, artifact_module):
    metadata_module = pytest.importorskip("server.app.metadata")
    monkeypatch.setattr(
        metadata_module,
        "ensure_metadata_session_id",
        lambda: "metadata-session",
        raising=False,
    )

    resolved = artifact_module._resolve_session_id("   ")
    assert resolved == "metadata-session"


def test_user_root_prefix_rejects_invalid_session_identifiers(artifact_module):
    with pytest.raises(ValueError):
        artifact_module._user_root_prefix(None)

    with pytest.raises(ValueError):
        artifact_module._user_root_prefix("   ")


def test_read_record_gcs_handles_download_failures_and_invalid_json(artifact_module, monkeypatch):
    monkeypatch.setattr(artifact_module, "_using_gcs", lambda: True, raising=False)

    monkeypatch.setattr(
        artifact_module,
        "download_bytes",
        lambda _blob: (_ for _ in ()).throw(RuntimeError("download failed")),
        raising=False,
    )
    assert artifact_module._read_record("cred-1", "session-a") is None

    monkeypatch.setattr(artifact_module, "download_bytes", lambda _blob: b"", raising=False)
    assert artifact_module._read_record("cred-1", "session-a") is None

    monkeypatch.setattr(artifact_module, "download_bytes", lambda _blob: b"\xff", raising=False)
    assert artifact_module._read_record("cred-1", "session-a") is None

    monkeypatch.setattr(artifact_module, "download_bytes", lambda _blob: b"{invalid", raising=False)
    assert artifact_module._read_record("cred-1", "session-a") is None


def test_write_record_gcs_uploads_json_payload(artifact_module, monkeypatch):
    monkeypatch.setattr(artifact_module, "_using_gcs", lambda: True, raising=False)

    uploads = []
    monkeypatch.setattr(
        artifact_module,
        "upload_bytes",
        lambda blob, payload, *, content_type=None: uploads.append((blob, payload, content_type)),
        raising=False,
    )

    artifact_module._write_record("cred-1", "session-a", {"payload": {"ok": True}})

    assert len(uploads) == 1
    blob, payload, content_type = uploads[0]
    assert "session-a" in blob
    assert payload.startswith(b"{")
    assert content_type == "application/json"


def test_delete_record_gcs_returns_false_when_existence_check_fails(artifact_module, monkeypatch):
    monkeypatch.setattr(artifact_module, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(
        artifact_module,
        "blob_exists",
        lambda _blob: (_ for _ in ()).throw(RuntimeError("exists failed")),
        raising=False,
    )
    monkeypatch.setattr(artifact_module, "delete_blob", lambda *_args, **_kwargs: None, raising=False)

    assert artifact_module._delete_record("cred-1", "session-a") is False


def test_delete_record_gcs_returns_false_when_delete_fails(artifact_module, monkeypatch):
    monkeypatch.setattr(artifact_module, "_using_gcs", lambda: True, raising=False)
    monkeypatch.setattr(artifact_module, "blob_exists", lambda _blob: True, raising=False)
    monkeypatch.setattr(
        artifact_module,
        "delete_blob",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("delete failed")),
        raising=False,
    )

    assert artifact_module._delete_record("cred-1", "session-a") is False


def test_load_credential_artifact_returns_none_for_non_mapping_payload(artifact_module, monkeypatch):
    monkeypatch.setattr(artifact_module, "_read_record", lambda *_args, **_kwargs: {"payload": [1, 2, 3]}, raising=False)

    assert artifact_module.load_credential_artifact("cred-1", session_id="session-a") is None


def test_store_credential_artifact_merge_handles_non_dict_existing_payload(artifact_module, monkeypatch):
    monkeypatch.setattr(
        artifact_module,
        "_read_record",
        lambda *_args, **_kwargs: {
            "storageId": "cred-1",
            "createdAt": 123.0,
            "updatedAt": 123.0,
            "payload": "not-a-dict",
        },
        raising=False,
    )

    written = {}

    def _capture_write(storage_id, session_id, record):
        written["storage_id"] = storage_id
        written["session_id"] = session_id
        written["record"] = record

    monkeypatch.setattr(artifact_module, "_write_record", _capture_write, raising=False)
    monkeypatch.setattr(artifact_module.time, "time", lambda: 456.0, raising=False)

    stored = artifact_module.store_credential_artifact(
        "cred-1",
        {"fresh": True},
        merge=True,
        session_id="session-a",
    )

    assert stored is True
    assert written["record"]["payload"] == {"fresh": True}
    assert written["record"]["createdAt"] == 123.0
    assert written["record"]["updatedAt"] == 456.0


def test_store_credential_artifact_returns_false_when_write_raises(artifact_module, monkeypatch):
    monkeypatch.setattr(
        artifact_module,
        "_write_record",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("write failed")),
        raising=False,
    )

    assert (
        artifact_module.store_credential_artifact(
            "cred-1",
            {"x": 1},
            session_id="session-a",
        )
        is False
    )


def test_delete_credential_artifact_rejects_invalid_storage_id(artifact_module):
    assert artifact_module.delete_credential_artifact("   ", session_id="session-a") is False


def test_using_gcs_depends_on_flag_and_bucket(monkeypatch):
    artifact_module = pytest.importorskip("server.app.credential_artifacts")

    monkeypatch.setattr(artifact_module, "gcs_enabled", lambda: True, raising=False)
    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "bucket-a")
    assert artifact_module._using_gcs() is True

    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    assert artifact_module._using_gcs() is False


def test_resolve_session_id_falls_back_for_non_string(monkeypatch, artifact_module):
    metadata_module = pytest.importorskip("server.app.metadata")
    monkeypatch.setattr(
        metadata_module,
        "ensure_metadata_session_id",
        lambda: "metadata-non-string-fallback",
        raising=False,
    )

    assert artifact_module._resolve_session_id(object()) == "metadata-non-string-fallback"


def test_delete_record_local_returns_false_on_oserror(artifact_module, monkeypatch):
    storage_id = "cred-oserror"
    path = artifact_module._artifact_path(storage_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("{}")

    monkeypatch.setattr(
        artifact_module.os,
        "remove",
        lambda _path: (_ for _ in ()).throw(OSError("remove failed")),
    )

    assert artifact_module._delete_record(storage_id, "session-a") is False


def test_load_credential_artifact_rejects_non_string_storage_id(artifact_module):
    assert artifact_module.load_credential_artifact(123, session_id="session-a") is None
