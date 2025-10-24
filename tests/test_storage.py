"""Tests for the credential storage helpers."""

from __future__ import annotations

import importlib
import pickle
import sys
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

server_pkg = types.ModuleType("server")
server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", server_pkg)

server_server_pkg = types.ModuleType("server.server")
server_server_pkg.__path__ = [str(_ROOT / "server" / "server")]
sys.modules.setdefault("server.server", server_server_pkg)

google_pkg = types.ModuleType("google")
google_pkg.__path__ = []
sys.modules.setdefault("google", google_pkg)

google_api_core_pkg = types.ModuleType("google.api_core")
google_api_core_pkg.__path__ = []
sys.modules.setdefault("google.api_core", google_api_core_pkg)

google_api_core_exceptions_pkg = types.ModuleType("google.api_core.exceptions")
setattr(google_api_core_exceptions_pkg, "NotFound", Exception)
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

storage = importlib.import_module("server.server.storage")


@pytest.fixture(autouse=True)
def _force_gcs(monkeypatch):
    """Ensure the storage helpers believe GCS is enabled during the tests."""

    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "test-bucket")
    monkeypatch.setattr(storage, "gcs_enabled", lambda: True)


def test_readkey_falls_back_to_legacy_gcs(monkeypatch):
    name = "alice@example.com"
    session_id = "session-one"
    legacy_blob = storage._legacy_credential_blob(name)
    new_blob = storage._credential_blob(name, session_id)

    observed = []

    def fake_download(blob_name: str):
        observed.append(blob_name)
        if blob_name == legacy_blob:
            return pickle.dumps([["legacy"]])
        return None

    monkeypatch.setattr(storage, "download_bytes", fake_download)

    result = storage.readkey(name, session_id=session_id)

    assert result == [["legacy"]]
    assert observed[0] == new_blob
    assert legacy_blob in observed


def test_iter_credentials_includes_legacy_entries(monkeypatch):
    name = "bob@example.com"
    session_id = "session-two"
    legacy_blob = storage._legacy_credential_blob(name)
    legacy_prefix = storage._build_search_prefix(storage._USER_FOLDER_PREFIX)
    new_prefix = storage._build_search_prefix(storage._credential_prefix(session_id))

    prefixes = []

    def fake_list_blob_names(prefix: str):
        prefixes.append(prefix)
        if prefix == legacy_prefix:
            yield legacy_blob

    def fake_download(blob_name: str):
        if blob_name == legacy_blob:
            return pickle.dumps([["from-legacy"]])
        return None

    monkeypatch.setattr(storage, "list_blob_names", fake_list_blob_names)
    monkeypatch.setattr(storage, "download_bytes", fake_download)

    entries = list(storage.iter_credentials(session_id=session_id))

    assert entries == [(name, [["from-legacy"]])]
    assert prefixes[0] == new_prefix
    assert legacy_prefix in prefixes


def test_iter_credentials_skips_nested_legacy_duplicates(monkeypatch):
    session_id = "session-three"
    primary_name = "dave@example.com"
    legacy_name = "ellen@example.com"

    primary_blob = storage._credential_blob(primary_name, session_id)
    legacy_blob = storage._legacy_credential_blob(legacy_name)

    new_prefix = storage._build_search_prefix(storage._credential_prefix(session_id))
    legacy_prefix = storage._build_search_prefix(storage._USER_FOLDER_PREFIX)

    def fake_list_blob_names(prefix: str):
        if prefix == new_prefix:
            yield primary_blob
        elif prefix == legacy_prefix:
            yield primary_blob
            yield legacy_blob

    payloads = {
        primary_blob: pickle.dumps([["primary"]]),
        legacy_blob: pickle.dumps([["legacy"]]),
    }

    monkeypatch.setattr(storage, "list_blob_names", fake_list_blob_names)
    monkeypatch.setattr(storage, "download_bytes", payloads.get)

    results = dict(storage.iter_credentials(session_id=session_id))

    assert results == {
        primary_name: [["primary"]],
        legacy_name: [["legacy"]],
    }


def test_delkey_attempts_legacy_cleanup(monkeypatch):
    name = "carol@example.com"
    session_id = "session-three"
    legacy_blob = storage._legacy_credential_blob(name)
    new_blob = storage._credential_blob(name, session_id)

    deleted = []

    def fake_delete(blob_name: str, *, missing_ok: bool = True):
        deleted.append((blob_name, missing_ok))

    monkeypatch.setattr(storage, "delete_blob", fake_delete)

    storage.delkey(name, session_id=session_id)

    assert deleted[0][0] == new_blob
    assert (legacy_blob, True) in deleted
