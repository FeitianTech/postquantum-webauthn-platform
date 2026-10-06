"""``storage.credential_artifacts``: a saved credential's artifact, on Cloud Storage and on disk.

On Cloud Storage the store runs over the in-memory bucket (``fake_gcs``): an object
the bucket refuses to read, or a check or delete it fails, is what an outage does.
On disk a folder where the record's file belongs is what a broken store does.
"""

from __future__ import annotations

import json
import logging
import os

import pytest

from server.app import visitor_session
from server.app.storage import common as storage_common
from server.app.storage import credential_artifacts
from server.app.storage.common import StorageReadError

from . import fake_gcs

SESSION = "session-a"


@pytest.fixture
def bucket(monkeypatch):
    return fake_gcs.install(monkeypatch, credential_artifacts)


def _blob(storage_id: str = "cred-1") -> str:
    return credential_artifacts._artifact_blob(storage_id, SESSION)


def test_an_artifact_is_stored_as_a_json_object(bucket):
    assert credential_artifacts.store_credential_artifact("cred-1", {"ok": True}, session_id=SESSION) is True

    record = json.loads(bucket.objects[_blob()][0])
    assert record["payload"] == {"ok": True}
    assert bucket.content_types[_blob()] == "application/json"
    assert credential_artifacts.load_credential_artifact("cred-1", session_id=SESSION) == {"ok": True}


def test_an_artifact_the_bucket_cannot_read_is_a_read_error_not_none(bucket):
    bucket.put(_blob(), b"{}")
    bucket.failing[_blob()] = fake_gcs.ServiceUnavailable("download failed")

    with pytest.raises(StorageReadError, match="Could not read") as raised:
        credential_artifacts.load_credential_artifact("cred-1", session_id=SESSION)

    assert isinstance(raised.value.__cause__, fake_gcs.ServiceUnavailable)


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"\xff-secret",
        b"{invalid-secret",
        b'["secret list"]',
        # JSON that json.loads still refuses: a ValueError past Python's digit limit, a RecursionError.
        b'{"secret": ' + b"1" * 5000 + b"}",
        b"[" * 200000 + b"]" * 200000,
    ],
)
def test_an_artifact_that_does_not_decode_is_named_in_the_log_and_skipped(bucket, caplog, content):
    bucket.put(_blob(), content)

    with caplog.at_level(logging.WARNING, logger=credential_artifacts.__name__):
        assert credential_artifacts.load_credential_artifact("cred-1", session_id=SESSION) is None

    messages = [record.getMessage() for record in caplog.records if record.name == credential_artifacts.__name__]
    assert len(messages) == 1 and _blob() in messages[0], messages
    assert "secret" not in messages[0]


def test_an_artifact_whose_payload_is_no_object_is_none(bucket):
    bucket.put(_blob(), json.dumps({"storageId": "cred-1", "payload": [1, 2, 3]}).encode())

    assert credential_artifacts.load_credential_artifact("cred-1", session_id=SESSION) is None


def test_a_merge_into_a_payload_that_is_no_object_starts_it_again_and_keeps_its_creation(bucket):
    stored = {"storageId": "cred-1", "createdAt": 123.0, "updatedAt": 123.0, "payload": "not-an-object"}
    bucket.put(_blob(), json.dumps(stored).encode())

    assert credential_artifacts.store_credential_artifact("cred-1", {"fresh": True}, merge=True, session_id=SESSION)

    record = json.loads(bucket.objects[_blob()][0])
    assert record["payload"] == {"fresh": True}
    assert record["createdAt"] == 123.0
    assert record["updatedAt"] > 123.0


@pytest.mark.parametrize("failing", ["exists", "delete"])
def test_a_delete_the_bucket_fails_is_reported_failed(bucket, monkeypatch, failing):
    credential_artifacts.store_credential_artifact("cred-1", {"ok": True}, session_id=SESSION)

    def _refused(*_args, **_kwargs):
        raise fake_gcs.ServiceUnavailable(f"{failing} failed")

    monkeypatch.setattr(fake_gcs.Blob, failing, _refused)

    assert credential_artifacts.delete_credential_artifact_with_status("cred-1", session_id=SESSION) == "failed"
    assert _blob() in bucket.objects


def _folder_where_the_record_belongs(storage_id: str) -> str:
    path = credential_artifacts._artifact_path(storage_id, SESSION)
    os.makedirs(path)
    return path


def test_on_disk_a_record_that_cannot_be_written_is_not_stored(artifacts_on_disk):
    _folder_where_the_record_belongs("cred-1")

    assert credential_artifacts.store_credential_artifact("cred-1", {"x": 1}, session_id=SESSION) is False


def test_on_disk_a_record_that_cannot_be_removed_is_reported_failed(artifacts_on_disk):
    path = _folder_where_the_record_belongs("cred-1")

    assert credential_artifacts.delete_credential_artifact_with_status("cred-1", session_id=SESSION) == "failed"
    assert os.path.isdir(path)


@pytest.fixture
def local_artifact_store(monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)


def test_store_load_delete_credential_artifact_round_trip_local(local_artifact_store):
    payload = {
        "storedCredential": {
            "credentialId": "cred-1",
            "signCount": 4,
        }
    }

    stored = credential_artifacts.store_credential_artifact(
        "cred-1",
        payload,
        session_id="session-a",
    )
    assert stored is True

    loaded = credential_artifacts.load_credential_artifact("cred-1", session_id="session-a")
    assert loaded == payload

    deleted = credential_artifacts.delete_credential_artifact_with_status("cred-1", session_id="session-a")
    assert deleted == "deleted"

    assert credential_artifacts.load_credential_artifact("cred-1", session_id="session-a") is None


def test_store_credential_artifact_rejects_invalid_inputs(local_artifact_store):
    assert (
        credential_artifacts.store_credential_artifact("   ", {"x": 1}, session_id="session-a")
        is False
    )
    assert (
        credential_artifacts.store_credential_artifact(None, {"x": 1}, session_id="session-a")
        is False
    )
    assert (
        credential_artifacts.store_credential_artifact("cred-1", "not-a-dict", session_id="session-a")
        is False
    )


def test_store_credential_artifact_merge_recursively_updates_nested_payload(local_artifact_store):
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

    assert credential_artifacts.store_credential_artifact(
        "cred-merge",
        initial_payload,
        session_id="session-a",
    )
    assert credential_artifacts.store_credential_artifact(
        "cred-merge",
        update_payload,
        merge=True,
        session_id="session-a",
    )

    loaded = credential_artifacts.load_credential_artifact("cred-merge", session_id="session-a")
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


def test_store_credential_artifact_merge_preserves_created_at_and_updates_updated_at(local_artifact_store, monkeypatch):
    time_values = iter([100.0, 250.0])
    monkeypatch.setattr(credential_artifacts.time, "time", lambda: next(time_values))

    assert credential_artifacts.store_credential_artifact(
        "cred-time",
        {"v": 1},
        session_id="session-a",
    )

    first_record = credential_artifacts._read_record("cred-time", "session-a")
    assert isinstance(first_record, dict)
    assert first_record["createdAt"] == 100.0
    assert first_record["updatedAt"] == 100.0

    assert credential_artifacts.store_credential_artifact(
        "cred-time",
        {"v": 2},
        merge=True,
        session_id="session-a",
    )

    second_record = credential_artifacts._read_record("cred-time", "session-a")
    assert isinstance(second_record, dict)
    assert second_record["createdAt"] == 100.0
    assert second_record["updatedAt"] == 250.0


def test_load_credential_artifact_returns_none_for_corrupt_json_local(local_artifact_store):
    path = credential_artifacts._artifact_path("cred-corrupt", "session-a")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("{broken-json")

    assert credential_artifacts.load_credential_artifact("cred-corrupt", session_id="session-a") is None


def test_delete_credential_artifact_reports_a_missing_artifact_as_absent(local_artifact_store):
    assert credential_artifacts.delete_credential_artifact_with_status("missing", session_id="session-a") == "absent"


def test_artifact_blob_is_session_scoped(local_artifact_store):
    first_blob = credential_artifacts._artifact_blob("cred-blob", "session-a")
    second_blob = credential_artifacts._artifact_blob("cred-blob", "session-b")

    assert first_blob != second_blob
    assert "session-a" in first_blob
    assert "session-b" in second_blob


def test_resolve_session_id_prefers_explicit_value(local_artifact_store):
    resolved = credential_artifacts._resolve_session_id(" explicit-session ")
    assert resolved == "explicit-session"


def test_resolve_session_id_falls_back_to_metadata_session(monkeypatch, local_artifact_store):
    monkeypatch.setattr(
        visitor_session,
        "ensure_id",
        lambda: "metadata-session",
    )

    resolved = credential_artifacts._resolve_session_id("   ")
    assert resolved == "metadata-session"


def test_artifact_prefix_rejects_invalid_session_identifiers(local_artifact_store):
    with pytest.raises(ValueError):
        credential_artifacts._artifact_prefix(None)

    with pytest.raises(ValueError):
        credential_artifacts._artifact_prefix("   ")


def test_read_record_local_raises_when_the_file_cannot_be_read(local_artifact_store):
    path = credential_artifacts._artifact_path("cred-dir", "session-a")
    # A directory where the file belongs: an OSError that is not "no such file".
    os.makedirs(path)
    with pytest.raises(StorageReadError):
        credential_artifacts._read_record("cred-dir", "session-a")
    with pytest.raises(StorageReadError):
        credential_artifacts.load_credential_artifact("cred-dir", session_id="session-a")


@pytest.mark.parametrize("stored", ["{broken-json", '{"n": ' + "1" * 5000 + "}", "[" * 200000 + "]" * 200000])
def test_a_local_merge_refuses_a_record_that_does_not_decode(local_artifact_store, stored):
    path = credential_artifacts._artifact_path("cred-corrupt", "session-a")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(stored)

    with pytest.raises(StorageReadError) as raised:
        credential_artifacts.store_credential_artifact("cred-corrupt", {"x": 1}, merge=True, session_id="session-a")
    assert isinstance(raised.value.__cause__, credential_artifacts.ArtifactUndecodable)
    with open(path, encoding="utf-8") as handle:
        assert handle.read() == stored
    # A store that replaces the record outright does not read it, and may.
    assert credential_artifacts.store_credential_artifact("cred-corrupt", {"x": 1}, session_id="session-a") is True


def test_delete_credential_artifact_rejects_invalid_storage_id(local_artifact_store):
    assert credential_artifacts.delete_credential_artifact_with_status("   ", session_id="session-a") == "failed"


def test_resolve_session_id_falls_back_for_non_string(monkeypatch, local_artifact_store):
    monkeypatch.setattr(
        visitor_session,
        "ensure_id",
        lambda: "metadata-non-string-fallback",
    )

    assert credential_artifacts._resolve_session_id(object()) == "metadata-non-string-fallback"


def test_load_credential_artifact_rejects_non_string_storage_id(local_artifact_store):
    assert credential_artifacts.load_credential_artifact(123, session_id="session-a") is None
