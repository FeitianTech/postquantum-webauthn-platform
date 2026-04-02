"""Tests for the Google Cloud Storage helpers."""

from __future__ import annotations

import importlib
import sys
import types

import pytest


def _install_google_stubs():
    google_pkg = types.ModuleType("google")
    google_pkg.__path__ = []
    sys.modules.setdefault("google", google_pkg)

    google_api_core_pkg = sys.modules.setdefault(
        "google.api_core", types.ModuleType("google.api_core")
    )
    google_api_core_pkg.__path__ = []
    google_api_core_exceptions_pkg = sys.modules.setdefault(
        "google.api_core.exceptions", types.ModuleType("google.api_core.exceptions")
    )

    class _BaseError(Exception):
        pass

    class _NotFound(_BaseError):
        pass

    class _GoogleAPICallError(_BaseError):
        pass

    class _RetryError(_BaseError):
        pass

    google_api_core_exceptions_pkg.NotFound = _NotFound
    google_api_core_exceptions_pkg.GoogleAPICallError = _GoogleAPICallError
    google_api_core_exceptions_pkg.RetryError = _RetryError
    google_api_core_pkg.exceptions = google_api_core_exceptions_pkg

    google_cloud_pkg = sys.modules.setdefault(
        "google.cloud", types.ModuleType("google.cloud")
    )
    google_cloud_pkg.__path__ = []
    google_cloud_storage_pkg = sys.modules.setdefault(
        "google.cloud.storage", types.ModuleType("google.cloud.storage")
    )

    class _DummyClient:
        def bucket(self, *_args, **_kwargs):  # pragma: no cover - defensive fallback
            raise RuntimeError("Not configured")

    google_cloud_storage_pkg.Client = _DummyClient
    google_cloud_pkg.storage = google_cloud_storage_pkg

    google_oauth_pkg = sys.modules.setdefault(
        "google.oauth2", types.ModuleType("google.oauth2")
    )
    google_oauth_pkg.__path__ = []
    google_service_account_pkg = sys.modules.setdefault(
        "google.oauth2.service_account",
        types.ModuleType("google.oauth2.service_account"),
    )

    class _DummyCredentials:
        @classmethod
        def from_service_account_file(cls, *_args, **_kwargs):
            return cls()

        @classmethod
        def from_service_account_info(cls, *_args, **_kwargs):
            return cls()

    google_service_account_pkg.Credentials = _DummyCredentials
    google_oauth_pkg.service_account = google_service_account_pkg

    google_auth_pkg = sys.modules.setdefault("google.auth", types.ModuleType("google.auth"))
    google_auth_pkg.__path__ = []
    google_auth_exceptions_pkg = sys.modules.setdefault(
        "google.auth.exceptions", types.ModuleType("google.auth.exceptions")
    )

    class _RefreshError(Exception):
        pass

    google_auth_exceptions_pkg.RefreshError = _RefreshError
    google_auth_pkg.exceptions = google_auth_exceptions_pkg


_install_google_stubs()
cloud_storage = importlib.import_module("server.app.cloud_storage")


def test_with_retry_succeeds_after_transient_error(monkeypatch):
    attempts = {"count": 0}

    class _Blob:
        def upload_from_string(self, *_args, **_kwargs):
            attempts["count"] += 1
            if attempts["count"] < 2:
                raise cloud_storage.gcs_exceptions.GoogleAPICallError("retry")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())

    sleeps = []
    monkeypatch.setattr(cloud_storage.time, "sleep", lambda delay: sleeps.append(delay))

    cloud_storage.upload_bytes("test", b"data")

    assert attempts["count"] == 2
    assert sleeps == [cloud_storage._DEFAULT_RETRY_BASE_DELAY]


def test_with_retry_raises_after_exhausting_attempts(monkeypatch):
    class _Blob:
        def upload_from_string(self, *_args, **_kwargs):
            raise cloud_storage.gcs_exceptions.GoogleAPICallError("fail")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())
    monkeypatch.setattr(cloud_storage.time, "sleep", lambda _delay: None)

    with pytest.raises(cloud_storage.gcs_exceptions.GoogleAPICallError):
        cloud_storage.upload_bytes("test", b"data")


def test_list_blob_names_retries_and_returns_results(monkeypatch):
    call_state = {"attempt": 0}

    class _Bucket:
        def list_blobs(self, prefix=None, **_kwargs):
            call_state["attempt"] += 1
            if call_state["attempt"] == 1:
                class _Iterator:
                    def __iter__(self):
                        return self

                    def __next__(self):
                        raise cloud_storage.gcs_exceptions.RetryError("transient")

                return _Iterator()
            return [types.SimpleNamespace(name="one"), types.SimpleNamespace(name="two")]

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())
    monkeypatch.setattr(cloud_storage.time, "sleep", lambda _delay: None)

    names = list(cloud_storage.list_blob_names("prefix"))

    assert names == ["one", "two"]
    assert call_state["attempt"] == 2


def test_download_bytes_handles_not_found(monkeypatch):
    class _Blob:
        def download_as_bytes(self):
            raise cloud_storage.gcs_exceptions.NotFound("missing")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())
    monkeypatch.setattr(cloud_storage.time, "sleep", lambda _delay: None)

    assert cloud_storage.download_bytes("missing") is None
