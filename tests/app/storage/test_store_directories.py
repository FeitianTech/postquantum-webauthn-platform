"""Every local store lives in the instance folder, the one place a deployment keeps.

Artifacts and session metadata used to default to server/runtime/, which
docker-compose does not mount, so a recreated container lost them; the
credentials were already in instance/. Each store's directory is read when the
store is used, not when the module is imported.
"""
from __future__ import annotations

import os

from server.app import credential_artifacts
from server.app.config import paths
from server.app.storage import credentials, session_metadata

_SETTINGS = (
    "FIDO_SERVER_CREDENTIAL_DIR",
    "FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR",
    "FIDO_SERVER_SESSION_METADATA_DIR",
)


def test_every_store_defaults_under_the_instance_folder(monkeypatch):
    for setting in _SETTINGS:
        monkeypatch.delenv(setting, raising=False)
    instance = paths.INSTANCE_ROOT

    # Paths only: nothing is created.
    assert credentials._local_filename("alice", "session-a") == os.path.join(
        instance, "session-credentials", "session-a", "alice_credential_data.json"
    )
    assert credential_artifacts._session_directory("session-a") == os.path.join(
        instance, "credential-artifacts", "session-a"
    )
    assert session_metadata._local_session_directory("session-a") == os.path.join(
        instance, "session-metadata", "session-a"
    )


def test_a_store_setting_is_read_when_the_store_is_used(monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(tmp_path / "credentials"))
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "metadata"))

    assert credentials._local_filename("alice", "session-a").startswith(str(tmp_path / "credentials") + os.sep)
    assert credential_artifacts._session_directory("session-a") == str(tmp_path / "artifacts" / "session-a")
    assert session_metadata._local_session_directory("session-a") == str(tmp_path / "metadata" / "session-a")
