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
