"""Tests for the credential storage helpers."""

from __future__ import annotations

import json
import pickle

import pytest

from server.app import visitor_session
from server.app.storage import cloud as storage_cloud
from server.app.storage import credentials


@pytest.fixture(autouse=True)
def _force_gcs(monkeypatch):
    """Ensure the storage helpers believe GCS is enabled during the tests."""

    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "test-bucket")
    monkeypatch.setattr(storage_cloud, "gcs_enabled", lambda: True)


def test_resolve_session_id_falls_back_to_metadata_session(monkeypatch):
    monkeypatch.setattr(
        visitor_session,
        "ensure_id",
        lambda: "fallback-session-id",
    )

    assert credentials._resolve_session_id("   ") == "fallback-session-id"


def test_save_uploads_payload_to_session_scoped_gcs_blob(monkeypatch):
    uploads = []

    def _upload(blob_name, payload, *, generation, content_type=None):
        uploads.append((blob_name, payload, content_type))
        return True

    monkeypatch.setattr(credentials, "upload_bytes_if_generation", _upload)

    value = [{"credential_data": "saved"}]
    assert credentials.save_if_unchanged("alice@example.com", value, 0, session_id="session-save")

    assert len(uploads) == 1
    blob_name, payload, content_type = uploads[0]
    assert blob_name == credentials._credential_blob("alice@example.com", "session-save")
    # Credentials are stored as JSON, never pickle: the payload must parse as
    # JSON and must not be loadable as a pickle.
    envelope = json.loads(payload.decode("utf-8"))
    assert envelope["version"] == 1
    assert envelope["encoding"] == "base64url"
    assert envelope["credentials"] == value
    assert blob_name.endswith("_credential_data.json")
    assert content_type == "application/json"
    with pytest.raises(pickle.UnpicklingError):
        pickle.loads(payload)
