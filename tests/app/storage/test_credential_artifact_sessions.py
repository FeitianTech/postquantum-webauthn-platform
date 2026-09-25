"""Local credential artifacts are kept per session, as they are on GCS.

On GCS an artifact lives under ``user-data/<session>/credential-artifacts/``;
locally every session's artifacts shared one flat directory, keyed by storage id
alone, so one session could load, overwrite or delete another's artifact by its
id. Local artifacts now live under ``<artifact dir>/<session>/``. Files in the
old flat layout are not read: they were local development data only.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from server.app import credential_artifacts as artifacts
from server.app.storage.common import InvalidStorageIdentifier

STORAGE_ID = "credential-1::artifact"
PAYLOAD = {"storedCredential": {"credentialId": "cred-1"}}


@pytest.fixture
def root(monkeypatch, tmp_path):
    monkeypatch.setattr(artifacts, "_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr(artifacts, "_using_gcs", lambda: False)
    return tmp_path


def test_another_session_cannot_load_an_artifact_by_its_id(root):
    assert artifacts.store_credential_artifact(STORAGE_ID, PAYLOAD, session_id="session-a")

    assert artifacts.load_credential_artifact(STORAGE_ID, session_id="session-b") is None
    assert artifacts.load_credential_artifact(STORAGE_ID, session_id="session-a") == PAYLOAD


def test_another_session_cannot_overwrite_or_delete_it(root):
    assert artifacts.store_credential_artifact(STORAGE_ID, PAYLOAD, session_id="session-a")

    assert artifacts.store_credential_artifact(STORAGE_ID, {"other": True}, session_id="session-b")
    assert artifacts.delete_credential_artifact_with_status(STORAGE_ID, session_id="session-b") == "deleted"
    assert artifacts.delete_credential_artifact_with_status(STORAGE_ID, session_id="session-b") == "absent"

    assert artifacts.load_credential_artifact(STORAGE_ID, session_id="session-a") == PAYLOAD


def test_the_record_lives_in_its_session_folder(root):
    assert artifacts.store_credential_artifact(STORAGE_ID, PAYLOAD, session_id="session-a")

    name = hashlib.sha256(STORAGE_ID.encode()).hexdigest() + ".json"
    with open(root / "session-a" / name, encoding="utf-8") as handle:
        assert json.load(handle)["payload"] == PAYLOAD
    assert not (root / name).exists()


def test_a_file_in_the_old_flat_layout_is_not_read(root):
    name = hashlib.sha256(STORAGE_ID.encode()).hexdigest() + ".json"
    (root / name).write_text(json.dumps({"storageId": STORAGE_ID, "payload": PAYLOAD}), encoding="utf-8")

    assert artifacts.load_credential_artifact(STORAGE_ID, session_id="session-a") is None


@pytest.mark.parametrize("session_id", ["../escape", "a/b", ".hidden"])
def test_a_session_id_that_could_leave_the_folder_is_refused(root, session_id):
    with pytest.raises(InvalidStorageIdentifier):
        artifacts.store_credential_artifact(STORAGE_ID, PAYLOAD, session_id=session_id)

    assert os.listdir(root) == []
