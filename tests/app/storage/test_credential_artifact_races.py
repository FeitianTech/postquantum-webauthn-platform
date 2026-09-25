"""A credential artifact merge never loses another writer's update.

The browser uploads an artifact with ``merge`` on and, separately, a snapshot of
the registration details, both into the same stored record. Merging reads the
record, merges the new keys in and writes it back. An in-process lock kept two
threads apart, but not two server processes, and not two Cloud Run instances
writing one GCS object: the second write replaced the first writer's keys.

On GCS the write is now conditional on the object generation it read, and a
lost race reads again and merges into what the winner wrote. Locally every
writer holds an ``flock`` on the record's ``.lock`` file across read, merge and
write.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import time

import pytest

from server.app import credential_artifacts as artifacts
from server.app.storage.common import StorageReadError

from . import fake_gcs

SESSION = "session-artifacts"
STORAGE_ID = "credential-1::artifact"
ORIGINAL = {"storedCredential": {"credentialId": "cred-1"}}


def _stored_payload(bucket=None):
    if bucket is not None:
        data, _generation = bucket.objects[artifacts._artifact_blob(STORAGE_ID, SESSION)]
        return json.loads(data)["payload"]
    return artifacts.load_credential_artifact(STORAGE_ID, session_id=SESSION)


@pytest.fixture
def gcs(monkeypatch):
    bucket = fake_gcs.install(monkeypatch, artifacts)
    assert artifacts.store_credential_artifact(STORAGE_ID, ORIGINAL, session_id=SESSION)
    return bucket


def _another_instance_merges(bucket, key):
    """After this request's first read, another instance writes ``key`` into the record."""

    blob_name = artifacts._artifact_blob(STORAGE_ID, SESSION)
    fired = []

    def _hook(name):
        if name == blob_name and not fired:
            fired.append(name)
            record = json.loads(bucket.objects[blob_name][0])
            record["payload"][key] = True
            bucket.put(blob_name, json.dumps(record).encode())

    bucket.on_download.append(_hook)
    return fired


def test_a_merge_racing_another_instance_keeps_both_updates(gcs):
    fired = _another_instance_merges(gcs, "fromTheOtherInstance")

    assert artifacts.store_credential_artifact(STORAGE_ID, {"registrationDetailSnapshot": {"a": 1}}, merge=True, session_id=SESSION)

    assert fired
    assert _stored_payload(gcs) == {
        "storedCredential": {"credentialId": "cred-1"},
        "fromTheOtherInstance": True,
        "registrationDetailSnapshot": {"a": 1},
    }


def test_a_merge_that_always_loses_stores_nothing_and_says_so(gcs):
    blob_name = artifacts._artifact_blob(STORAGE_ID, SESSION)
    writes = []

    def _always_someone_else(name):
        if name == blob_name:
            writes.append(name)
            gcs.put(blob_name, gcs.objects[blob_name][0])

    gcs.on_download.append(_always_someone_else)

    assert artifacts.store_credential_artifact(STORAGE_ID, {"late": True}, merge=True, session_id=SESSION) is False
    assert "late" not in _stored_payload(gcs)
    assert len(writes) == 8


def test_a_merge_that_cannot_read_the_record_does_not_overwrite_it(gcs, monkeypatch):
    real_blob = gcs.blob

    class _Unreadable:
        def __init__(self, name):
            self._blob = real_blob(name)
            self.generation = None

        def download_as_bytes(self):
            raise RuntimeError("bucket unreachable")

        def __getattr__(self, item):
            return getattr(self._blob, item)

    monkeypatch.setattr(gcs, "blob", _Unreadable)

    # Not "unable to store" (400): the store could not be read, which the app answers with 503.
    with pytest.raises(StorageReadError):
        artifacts.store_credential_artifact(STORAGE_ID, {"late": True}, merge=True, session_id=SESSION)
    monkeypatch.setattr(gcs, "blob", real_blob)
    assert _stored_payload(gcs) == ORIGINAL


def test_a_merge_refuses_a_record_that_does_not_decode_rather_than_overwrite_it(gcs):
    blob_name = artifacts._artifact_blob(STORAGE_ID, SESSION)
    gcs.put(blob_name, b"{not json")

    with pytest.raises(StorageReadError) as raised:
        artifacts.store_credential_artifact(STORAGE_ID, {"late": True}, merge=True, session_id=SESSION)
    assert isinstance(raised.value.__cause__, artifacts.ArtifactUndecodable)
    assert gcs.objects[blob_name][0] == b"{not json"


def test_a_merge_whose_write_landed_but_whose_reply_was_lost_is_stored(gcs, monkeypatch):
    # A conditional upload is one attempt; a reply lost after the write landed
    # used to answer "Unable to store artifact" for an artifact that was stored.
    original = artifacts.upload_bytes_if_generation

    def _lands_then_fails(*args, **kwargs):
        original(*args, **kwargs)
        raise ConnectionError("connection reset after the write")

    monkeypatch.setattr(artifacts, "upload_bytes_if_generation", _lands_then_fails)

    assert artifacts.store_credential_artifact(
        STORAGE_ID, {"registrationDetailSnapshot": {"a": 1}}, merge=True, session_id=SESSION
    ) is True
    assert _stored_payload(gcs) == {**ORIGINAL, "registrationDetailSnapshot": {"a": 1}}


def test_a_merge_whose_write_failed_before_it_landed_says_so(gcs, monkeypatch):
    def _fails(*_args, **_kwargs):
        raise ConnectionError("bucket unreachable")

    monkeypatch.setattr(artifacts, "upload_bytes_if_generation", _fails)

    assert artifacts.store_credential_artifact(STORAGE_ID, {"late": True}, merge=True, session_id=SESSION) is False
    assert _stored_payload(gcs) == ORIGINAL


def test_a_lost_reply_that_cannot_be_checked_is_not_reported_as_stored(gcs, monkeypatch):
    blob_name = artifacts._artifact_blob(STORAGE_ID, SESSION)
    original = artifacts.upload_bytes_if_generation

    def _lands_then_fails_and_goes_dark(*args, **kwargs):
        original(*args, **kwargs)
        gcs.failing[blob_name] = fake_gcs.ServiceUnavailable("503")
        raise ConnectionError("connection reset after the write")

    monkeypatch.setattr(artifacts, "upload_bytes_if_generation", _lands_then_fails_and_goes_dark)

    assert artifacts.store_credential_artifact(STORAGE_ID, {"late": True}, merge=True, session_id=SESSION) is False


def test_a_lost_reply_counts_as_stored_only_if_the_record_holds_every_merged_value(gcs, monkeypatch):
    blob_name = artifacts._artifact_blob(STORAGE_ID, SESSION)

    def _someone_else_wins_then_the_reply_is_lost(*_args, **_kwargs):
        record = json.loads(gcs.objects[blob_name][0])
        record["payload"]["registrationDetailSnapshot"] = {"a": 2}
        gcs.put(blob_name, json.dumps(record).encode())
        raise ConnectionError("connection reset")

    monkeypatch.setattr(artifacts, "upload_bytes_if_generation", _someone_else_wins_then_the_reply_is_lost)

    assert artifacts.store_credential_artifact(
        STORAGE_ID, {"registrationDetailSnapshot": {"a": 1}}, merge=True, session_id=SESSION
    ) is False


def _merge_in_a_process(root, key, start):
    os.environ.pop("FIDO_SERVER_GCS_ENABLED", None)
    from server.app import credential_artifacts as child

    child._ARTIFACT_DIR = root
    # The read a merge extends: slowed so that, without the lock, the two merges'
    # read-then-write windows overlap and one update is lost.
    read = child._record_to_merge_into
    slowed = []

    def _slow_read(*args, **kwargs):
        record = read(*args, **kwargs)
        slowed.append(True)
        time.sleep(0.5)
        return record

    child._record_to_merge_into = _slow_read
    start.wait()
    assert child.store_credential_artifact(STORAGE_ID, {key: True}, merge=True, session_id=SESSION)
    # Were the read not the one the merge does, the test would pass without the lock.
    assert slowed == [True]


def test_two_processes_merging_one_artifact_keep_both_updates(monkeypatch, tmp_path):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setattr(artifacts, "_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr(artifacts, "_using_gcs", lambda: False)
    assert artifacts.store_credential_artifact(STORAGE_ID, ORIGINAL, session_id=SESSION)

    context = multiprocessing.get_context("spawn")
    start = context.Event()
    processes = [
        context.Process(target=_merge_in_a_process, args=(str(tmp_path), key, start)) for key in ("first", "second")
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=120)

    assert [process.exitcode for process in processes] == [0, 0]
    assert _stored_payload() == {**ORIGINAL, "first": True, "second": True}


def test_a_local_delete_takes_the_record_lock_only_when_there_is_a_record(monkeypatch, tmp_path):
    monkeypatch.setattr(artifacts, "_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr(artifacts, "_using_gcs", lambda: False)

    assert artifacts.delete_credential_artifact_with_status("absent-id", session_id=SESSION) == "absent"
    assert not any(name.endswith(".lock") for name in os.listdir(tmp_path)) if tmp_path.exists() else True

    assert artifacts.store_credential_artifact(STORAGE_ID, ORIGINAL, session_id=SESSION)
    assert artifacts.delete_credential_artifact_with_status(STORAGE_ID, session_id=SESSION) == "deleted"
    assert artifacts.load_credential_artifact(STORAGE_ID, session_id=SESSION) is None
