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
