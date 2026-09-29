"""Tests for the credential storage helpers."""

from __future__ import annotations

import importlib
import json
import pickle
import sys
import types
from pathlib import Path

import pytest


def _discover_repo_root(start: Path) -> Path:
    for candidate in start.parents:
        if (candidate / "server").is_dir() and (candidate / "tests").is_dir():
            return candidate

    return start.parents[3]


_ROOT = _discover_repo_root(Path(__file__).resolve())

server_pkg = types.ModuleType("server")
server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", server_pkg)

server_server_pkg = types.ModuleType("server.app")
server_server_pkg.__path__ = [str(_ROOT / "server" / "app")]
sys.modules.setdefault("server.app", server_server_pkg)

google_pkg = types.ModuleType("google")
google_pkg.__path__ = []
sys.modules.setdefault("google", google_pkg)

google_api_core_pkg = types.ModuleType("google.api_core")
google_api_core_pkg.__path__ = []
sys.modules.setdefault("google.api_core", google_api_core_pkg)

google_api_core_exceptions_pkg = types.ModuleType("google.api_core.exceptions")
setattr(google_api_core_exceptions_pkg, "NotFound", Exception)
setattr(google_api_core_exceptions_pkg, "GoogleAPICallError", Exception)
setattr(google_api_core_exceptions_pkg, "RetryError", Exception)
sys.modules.setdefault("google.api_core.exceptions", google_api_core_exceptions_pkg)

google_cloud_pkg = types.ModuleType("google.cloud")
google_cloud_pkg.__path__ = []
sys.modules.setdefault("google.cloud", google_cloud_pkg)

class _DummyClient:
    def __init__(self, *args, **kwargs):
        pass

    def bucket(self, *_args, **_kwargs):
        raise RuntimeError("Cloud interactions are not available in tests")


google_cloud_storage_pkg = types.ModuleType("google.cloud.storage")
setattr(google_cloud_storage_pkg, "Client", _DummyClient)
sys.modules.setdefault("google.cloud.storage", google_cloud_storage_pkg)

google_oauth_pkg = types.ModuleType("google.oauth2")
google_oauth_pkg.__path__ = []
sys.modules.setdefault("google.oauth2", google_oauth_pkg)


class _DummyCredentials:
    @classmethod
    def from_service_account_file(cls, *_args, **_kwargs):
        return cls()

    @classmethod
    def from_service_account_info(cls, *_args, **_kwargs):
        return cls()


google_service_account_pkg = types.ModuleType("google.oauth2.service_account")
setattr(google_service_account_pkg, "Credentials", _DummyCredentials)
sys.modules.setdefault("google.oauth2.service_account", google_service_account_pkg)

google_pkg.api_core = google_api_core_pkg
google_pkg.cloud = google_cloud_pkg
google_pkg.oauth2 = google_oauth_pkg
google_api_core_pkg.exceptions = google_api_core_exceptions_pkg
google_cloud_pkg.storage = google_cloud_storage_pkg
google_oauth_pkg.service_account = google_service_account_pkg
google_auth_pkg = types.ModuleType("google.auth")
google_auth_pkg.__path__ = []
sys.modules.setdefault("google.auth", google_auth_pkg)
google_auth_exceptions_pkg = types.ModuleType("google.auth.exceptions")
setattr(google_auth_exceptions_pkg, "RefreshError", Exception)
sys.modules.setdefault("google.auth.exceptions", google_auth_exceptions_pkg)
google_auth_pkg.exceptions = google_auth_exceptions_pkg

credentials = importlib.import_module("server.app.storage.credentials")
StorageReadError = importlib.import_module("server.app.storage.common").StorageReadError


@pytest.fixture(autouse=True)
def _force_gcs(monkeypatch):
    """Ensure the storage helpers believe GCS is enabled during the tests."""

    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "test-bucket")
    monkeypatch.setattr(credentials, "gcs_enabled", lambda: True)


def test_readkey_falls_back_to_legacy_gcs(monkeypatch):
    name = "alice@example.com"
    session_id = "session-one"
    legacy_blob = credentials._legacy_credential_blob(name)
    new_blob = credentials._credential_blob(name, session_id)

    observed = []

    def fake_download(blob_name: str):
        observed.append(blob_name)
        if blob_name == legacy_blob:
            return pickle.dumps([["legacy"]])
        return None

    monkeypatch.setattr(credentials, "download_bytes", fake_download)

    result = credentials.readkey(name, session_id=session_id)

    assert result == [["legacy"]]
    assert observed[0] == new_blob
    assert legacy_blob in observed


def test_readkey_returns_empty_list_for_corrupted_payload(monkeypatch):
    monkeypatch.setattr(credentials, "download_bytes", lambda _blob_name: b"not-a-valid-pickle")

    result = credentials.readkey("broken@example.com", session_id="session-corrupt")

    assert result == []


def test_resolve_session_id_falls_back_to_metadata_session(monkeypatch):
    metadata_module = importlib.import_module("server.app.webauthn.metadata")
    monkeypatch.setattr(
        metadata_module,
        "ensure_metadata_session_id",
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
    with pytest.raises(Exception):
        pickle.loads(payload)


def test_readkey_raises_when_a_gcs_download_fails(monkeypatch):
    calls = []

    def fake_download(blob_name: str):
        calls.append(blob_name)
        raise RuntimeError("temporary failure")

    monkeypatch.setattr(credentials, "download_bytes", fake_download)

    # Not on to the legacy copies, and not []: either would answer with stale records or none.
    with pytest.raises(StorageReadError):
        credentials.readkey("alice@example.com", session_id="session-read")
    assert len(calls) == 1


def test_readkey_reads_past_copies_that_are_not_there(monkeypatch):
    calls = []
    monkeypatch.setattr(credentials, "download_bytes", lambda blob_name: calls.append(blob_name))

    assert credentials.readkey("alice@example.com", session_id="session-read") == []
    assert len(calls) == 4
