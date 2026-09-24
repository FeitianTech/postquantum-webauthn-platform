import os

import pytest


@pytest.fixture
def artifact_module(monkeypatch, tmp_path):
    module = pytest.importorskip("server.app.credential_artifacts")
    monkeypatch.setattr(module, "_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr(module, "_using_gcs", lambda: False)
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


def test_store_credential_artifact_merge_preserves_created_at_and_updates_updated_at(artifact_module, monkeypatch):
    time_values = iter([100.0, 250.0])
    monkeypatch.setattr(artifact_module.time, "time", lambda: next(time_values))

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
    path = artifact_module._artifact_path("cred-corrupt", "session-a")
    os.makedirs(os.path.dirname(path), exist_ok=True)
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
    metadata_module = pytest.importorskip("server.app.webauthn.metadata")
    monkeypatch.setattr(
        metadata_module,
        "ensure_metadata_session_id",
        lambda: "metadata-session",
    )

    resolved = artifact_module._resolve_session_id("   ")
    assert resolved == "metadata-session"


def test_user_root_prefix_rejects_invalid_session_identifiers(artifact_module):
    with pytest.raises(ValueError):
        artifact_module._user_root_prefix(None)

    with pytest.raises(ValueError):
        artifact_module._user_root_prefix("   ")


def test_read_record_gcs_raises_on_a_download_error_and_skips_what_does_not_decode(artifact_module, monkeypatch, caplog):
    from server.app.storage.common import StorageReadError

    monkeypatch.setattr(artifact_module, "_using_gcs", lambda: True)
    blob_name = artifact_module._artifact_blob("cred-1", "session-a")

    # A download that fails is not "no artifact": the store could not be read.
    monkeypatch.setattr(
        artifact_module,
        "download_bytes",
        lambda _blob: (_ for _ in ()).throw(RuntimeError("download failed")),
    )
    with pytest.raises(StorageReadError, match="Could not read") as raised:
        artifact_module._read_record("cred-1", "session-a")
    assert isinstance(raised.value.__cause__, RuntimeError)

    # Nothing stored is fine.
    monkeypatch.setattr(artifact_module, "download_bytes", lambda _blob: None)
    assert artifact_module._read_record("cred-1", "session-a") is None

    # Content that does not decode is logged by name, never its content, and skipped.
    for content in (b"", b"\xff-secret", b"{invalid-secret", b'["secret list"]'):
        monkeypatch.setattr(artifact_module, "download_bytes", lambda _blob, content=content: content)
        caplog.clear()
        with caplog.at_level("WARNING", logger="server.app.credential_artifacts"):
            assert artifact_module._read_record("cred-1", "session-a") is None
        messages = [record.getMessage() for record in caplog.records]
        assert len(messages) == 1 and blob_name in messages[0], messages
        assert "secret" not in messages[0]


def test_read_record_local_raises_when_the_file_cannot_be_read(artifact_module):
    from server.app.storage.common import StorageReadError

    path = artifact_module._artifact_path("cred-dir", "session-a")
    # A directory where the file belongs: an OSError that is not "no such file".
    os.makedirs(path)
    with pytest.raises(StorageReadError):
        artifact_module._read_record("cred-dir", "session-a")
    with pytest.raises(StorageReadError):
        artifact_module.load_credential_artifact("cred-dir", session_id="session-a")


def test_a_local_merge_refuses_a_record_that_does_not_decode(artifact_module):
    from server.app.storage.common import StorageReadError

    path = artifact_module._artifact_path("cred-corrupt", "session-a")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("{broken-json")

    with pytest.raises(StorageReadError) as raised:
        artifact_module.store_credential_artifact("cred-corrupt", {"x": 1}, merge=True, session_id="session-a")
    assert isinstance(raised.value.__cause__, artifact_module.ArtifactUndecodable)
    with open(path, encoding="utf-8") as handle:
        assert handle.read() == "{broken-json"
    # A store that replaces the record outright does not read it, and may.
    assert artifact_module.store_credential_artifact("cred-corrupt", {"x": 1}, session_id="session-a") is True


def test_write_record_gcs_uploads_json_payload(artifact_module, monkeypatch):
    monkeypatch.setattr(artifact_module, "_using_gcs", lambda: True)

    uploads = []
    monkeypatch.setattr(
        artifact_module,
        "upload_bytes",
        lambda blob, payload, *, content_type=None: uploads.append((blob, payload, content_type)),
    )

    artifact_module._write_record("cred-1", "session-a", {"payload": {"ok": True}})

    assert len(uploads) == 1
    blob, payload, content_type = uploads[0]
    assert "session-a" in blob
    assert payload.startswith(b"{")
    assert content_type == "application/json"


def test_delete_record_gcs_returns_false_when_existence_check_fails(artifact_module, monkeypatch):
    monkeypatch.setattr(artifact_module, "_using_gcs", lambda: True)
    monkeypatch.setattr(
        artifact_module,
        "blob_exists",
        lambda _blob: (_ for _ in ()).throw(RuntimeError("exists failed")),
    )
    monkeypatch.setattr(artifact_module, "delete_blob", lambda *_args, **_kwargs: None)

    assert artifact_module._delete_record("cred-1", "session-a") is False


def test_delete_record_gcs_returns_false_when_delete_fails(artifact_module, monkeypatch):
    monkeypatch.setattr(artifact_module, "_using_gcs", lambda: True)
    monkeypatch.setattr(artifact_module, "blob_exists", lambda _blob: True)
    monkeypatch.setattr(
        artifact_module,
        "delete_blob",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("delete failed")),
    )

    assert artifact_module._delete_record("cred-1", "session-a") is False


def test_load_credential_artifact_returns_none_for_non_mapping_payload(artifact_module, monkeypatch):
    monkeypatch.setattr(artifact_module, "_read_record", lambda *_args, **_kwargs: {"payload": [1, 2, 3]})

    assert artifact_module.load_credential_artifact("cred-1", session_id="session-a") is None


def test_store_credential_artifact_merge_handles_non_dict_existing_payload(artifact_module, monkeypatch):
    monkeypatch.setattr(
        artifact_module,
        "_record_to_merge_into",
        lambda *_args, **_kwargs: {
            "storageId": "cred-1",
            "createdAt": 123.0,
            "updatedAt": 123.0,
            "payload": "not-a-dict",
        },
    )

    written = {}

    def _capture_write(storage_id, session_id, record):
        written["storage_id"] = storage_id
        written["session_id"] = session_id
        written["record"] = record

    monkeypatch.setattr(artifact_module, "_write_record", _capture_write)
    monkeypatch.setattr(artifact_module.time, "time", lambda: 456.0)

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

    monkeypatch.setattr(artifact_module, "gcs_enabled", lambda: True)
    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "bucket-a")
    assert artifact_module._using_gcs() is True

    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    assert artifact_module._using_gcs() is False


def test_resolve_session_id_falls_back_for_non_string(monkeypatch, artifact_module):
    metadata_module = pytest.importorskip("server.app.webauthn.metadata")
    monkeypatch.setattr(
        metadata_module,
        "ensure_metadata_session_id",
        lambda: "metadata-non-string-fallback",
    )

    assert artifact_module._resolve_session_id(object()) == "metadata-non-string-fallback"


def test_delete_record_local_returns_false_on_oserror(artifact_module, monkeypatch):
    storage_id = "cred-oserror"
    path = artifact_module._artifact_path(storage_id, "session-a")
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
