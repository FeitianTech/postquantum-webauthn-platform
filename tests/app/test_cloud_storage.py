"""Tests for the Google Cloud Storage helpers."""

from __future__ import annotations

import json
import importlib
import sys
import types
from datetime import datetime, timezone

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


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, None),
        ("", False),
        ("0", False),
        ("false", False),
        ("off", False),
        ("no", False),
        ("1", True),
        ("true", True),
        ("yes", True),
        ("on", True),
        ("unexpected", True),
    ],
)
def test_env_flag_interprets_values(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("TEST_FLAG", raising=False)
    else:
        monkeypatch.setenv("TEST_FLAG", raw)

    assert cloud_storage._env_flag("TEST_FLAG") is expected


def test_gcs_enabled_defaults_to_false_when_env_missing(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)

    assert cloud_storage.gcs_enabled() is False


def test_gcs_enabled_honors_explicit_true_false(monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_GCS_ENABLED", "1")
    assert cloud_storage.gcs_enabled() is True

    monkeypatch.setenv("FIDO_SERVER_GCS_ENABLED", "false")
    assert cloud_storage.gcs_enabled() is False


def test_build_client_prefers_service_account_file(monkeypatch):
    class _Creds:
        project_id = "file-project"

    observed = {}

    def _from_file(path):
        observed["credentials_file"] = path
        return _Creds()

    def _client_factory(*args, **kwargs):
        observed["client_args"] = args
        observed["client_kwargs"] = kwargs
        return {"args": args, "kwargs": kwargs}

    monkeypatch.setenv("FIDO_SERVER_GCS_CREDENTIALS_FILE", "/tmp/service-account.json")
    monkeypatch.delenv("FIDO_SERVER_GCS_CREDENTIALS_JSON", raising=False)
    monkeypatch.delenv("FIDO_SERVER_GCS_PROJECT", raising=False)
    monkeypatch.setattr(
        cloud_storage.service_account.Credentials,
        "from_service_account_file",
        _from_file,
    )
    monkeypatch.setattr(cloud_storage.storage, "Client", _client_factory)

    client = cloud_storage._build_client()

    assert observed["credentials_file"] == "/tmp/service-account.json"
    assert observed["client_args"] == ()
    assert observed["client_kwargs"] == {
        "project": "file-project",
        "credentials": client["kwargs"]["credentials"],
    }
    assert isinstance(client["kwargs"]["credentials"], _Creds)


def test_build_client_file_credentials_respects_project_override(monkeypatch):
    class _Creds:
        project_id = "file-project"

    observed = {}

    monkeypatch.setenv("FIDO_SERVER_GCS_CREDENTIALS_FILE", "/tmp/service-account.json")
    monkeypatch.setenv("FIDO_SERVER_GCS_PROJECT", "override-project")
    monkeypatch.delenv("FIDO_SERVER_GCS_CREDENTIALS_JSON", raising=False)
    monkeypatch.setattr(
        cloud_storage.service_account.Credentials,
        "from_service_account_file",
        lambda _path: _Creds(),
    )

    def _client_factory(*args, **kwargs):
        observed["project"] = kwargs.get("project")
        observed["credentials"] = kwargs.get("credentials")
        return "client"

    monkeypatch.setattr(cloud_storage.storage, "Client", _client_factory)

    assert cloud_storage._build_client() == "client"
    assert observed["project"] == "override-project"
    assert isinstance(observed["credentials"], _Creds)


def test_build_client_uses_service_account_info_json(monkeypatch):
    observed = {}
    payload = {
        "type": "service_account",
        "project_id": "json-project",
        "private_key_id": "abc",
        "private_key": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n",
        "client_email": "test@example.com",
        "client_id": "123",
        "token_uri": "https://oauth2.googleapis.com/token",
    }

    class _Creds:
        pass

    monkeypatch.delenv("FIDO_SERVER_GCS_CREDENTIALS_FILE", raising=False)
    monkeypatch.setenv("FIDO_SERVER_GCS_CREDENTIALS_JSON", json.dumps(payload))
    monkeypatch.delenv("FIDO_SERVER_GCS_PROJECT", raising=False)

    def _from_info(info):
        observed["info"] = info
        return _Creds()

    def _client_factory(*args, **kwargs):
        observed["kwargs"] = kwargs
        return "json-client"

    monkeypatch.setattr(
        cloud_storage.service_account.Credentials,
        "from_service_account_info",
        _from_info,
    )
    monkeypatch.setattr(cloud_storage.storage, "Client", _client_factory)

    assert cloud_storage._build_client() == "json-client"
    assert observed["info"]["project_id"] == "json-project"
    assert observed["kwargs"]["project"] == "json-project"
    assert isinstance(observed["kwargs"]["credentials"], _Creds)


def test_build_client_with_project_override_only(monkeypatch):
    observed = {}

    monkeypatch.delenv("FIDO_SERVER_GCS_CREDENTIALS_FILE", raising=False)
    monkeypatch.delenv("FIDO_SERVER_GCS_CREDENTIALS_JSON", raising=False)
    monkeypatch.setenv("FIDO_SERVER_GCS_PROJECT", "override-only")

    def _client_factory(*args, **kwargs):
        observed["args"] = args
        observed["kwargs"] = kwargs
        return "project-client"

    monkeypatch.setattr(cloud_storage.storage, "Client", _client_factory)

    assert cloud_storage._build_client() == "project-client"
    assert observed["args"] == ()
    assert observed["kwargs"] == {"project": "override-only"}


def test_build_client_defaults_to_storage_client_without_overrides(monkeypatch):
    observed = {}

    monkeypatch.delenv("FIDO_SERVER_GCS_CREDENTIALS_FILE", raising=False)
    monkeypatch.delenv("FIDO_SERVER_GCS_CREDENTIALS_JSON", raising=False)
    monkeypatch.delenv("FIDO_SERVER_GCS_PROJECT", raising=False)

    def _client_factory(*args, **kwargs):
        observed["args"] = args
        observed["kwargs"] = kwargs
        return "default-client"

    monkeypatch.setattr(cloud_storage.storage, "Client", _client_factory)

    assert cloud_storage._build_client() == "default-client"
    assert observed["args"] == ()
    assert observed["kwargs"] == {}


def test_ensure_bucket_raises_when_gcs_disabled(monkeypatch):
    monkeypatch.setattr(cloud_storage, "_CLIENT", None)
    monkeypatch.setattr(cloud_storage, "_BUCKET", None)
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: False)

    with pytest.raises(RuntimeError, match="disabled"):
        cloud_storage._ensure_bucket()


def test_ensure_bucket_requires_bucket_configuration(monkeypatch):
    monkeypatch.setattr(cloud_storage, "_CLIENT", None)
    monkeypatch.setattr(cloud_storage, "_BUCKET", None)
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: True)
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)

    with pytest.raises(RuntimeError, match="FIDO_SERVER_GCS_BUCKET"):
        cloud_storage._ensure_bucket()


def test_ensure_bucket_builds_and_caches_bucket(monkeypatch):
    build_calls = {"count": 0}
    bucket_calls = {"count": 0}
    bucket_value = object()

    class _Client:
        def bucket(self, name):
            bucket_calls["count"] += 1
            assert name == "cache-bucket"
            return bucket_value

    def _build_client():
        build_calls["count"] += 1
        return _Client()

    monkeypatch.setattr(cloud_storage, "_CLIENT", None)
    monkeypatch.setattr(cloud_storage, "_BUCKET", None)
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: True)
    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "cache-bucket")
    monkeypatch.setattr(cloud_storage, "_build_client", _build_client)

    first = cloud_storage._ensure_bucket()
    second = cloud_storage._ensure_bucket()

    assert first is bucket_value
    assert second is bucket_value
    assert build_calls["count"] == 1
    assert bucket_calls["count"] == 1


def test_ensure_ready_retries_until_bucket_list_succeeds(monkeypatch):
    calls = {"count": 0}
    sleeps = []

    class _Bucket:
        def list_blobs(self, max_results=1):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("temporary failure")
            assert max_results == 1
            return []

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())
    monkeypatch.setattr(cloud_storage.time, "sleep", lambda delay: sleeps.append(delay))

    cloud_storage.ensure_ready(max_attempts=3, retry_delay=0.25)

    assert calls["count"] == 2
    assert sleeps == [0.25]


def test_ensure_ready_raises_last_error_after_max_attempts(monkeypatch):
    sleeps = []

    class _Bucket:
        def list_blobs(self, max_results=1):
            raise RuntimeError("still failing")

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())
    monkeypatch.setattr(cloud_storage.time, "sleep", lambda delay: sleeps.append(delay))

    with pytest.raises(RuntimeError, match="still failing"):
        cloud_storage.ensure_ready(max_attempts=3, retry_delay=0.1)

    assert sleeps == [0.1, 0.1]


def test_with_retry_does_not_retry_not_found(monkeypatch):
    calls = {"count": 0}
    sleeps = []

    def _operation():
        calls["count"] += 1
        raise cloud_storage.gcs_exceptions.NotFound("missing")

    monkeypatch.setattr(cloud_storage.time, "sleep", lambda delay: sleeps.append(delay))

    with pytest.raises(cloud_storage.gcs_exceptions.NotFound):
        cloud_storage._with_retry(_operation)

    assert calls["count"] == 1
    assert sleeps == []


def test_with_retry_uses_exponential_backoff(monkeypatch):
    calls = {"count": 0}
    sleeps = []

    def _operation():
        calls["count"] += 1
        if calls["count"] < 3:
            raise cloud_storage.gcs_exceptions.GoogleAPICallError("transient")
        return "ok"

    monkeypatch.setattr(cloud_storage.time, "sleep", lambda delay: sleeps.append(delay))

    result = cloud_storage._with_retry(_operation)

    assert result == "ok"
    assert sleeps == [0.5, 1.0]


def test_build_blob_name_normalizes_components_and_prefix():
    blob = cloud_storage.build_blob_name(
        "/session-id/",
        "/credentials/",
        "file.pkl",
        prefix=" /user-data/ ",
    )

    assert blob == "user-data/session-id/credentials/file.pkl"


def test_build_blob_name_raises_for_empty_path_components():
    with pytest.raises(ValueError, match="Invalid blob path components"):
        cloud_storage.build_blob_name("", "/", prefix="/prefix/")


def test_delete_blob_honors_missing_ok_false(monkeypatch):
    class _Blob:
        def delete(self):
            raise cloud_storage.gcs_exceptions.NotFound("missing")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())

    with pytest.raises(cloud_storage.gcs_exceptions.NotFound):
        cloud_storage.delete_blob("missing", missing_ok=False)


def test_blob_exists_casts_result_to_bool(monkeypatch):
    class _Blob:
        def exists(self):
            return "truthy"

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())

    assert cloud_storage.blob_exists("any") is True


def test_blob_updated_timestamp_returns_none_when_blob_missing(monkeypatch):
    class _Blob:
        updated = None

        def reload(self):
            raise cloud_storage.gcs_exceptions.NotFound("missing")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())

    assert cloud_storage.blob_updated_timestamp("missing") is None


def test_blob_updated_timestamp_returns_none_when_updated_unset(monkeypatch):
    class _Blob:
        updated = None

        def reload(self):
            return None

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())

    assert cloud_storage.blob_updated_timestamp("existing") is None


def test_blob_updated_timestamp_returns_epoch_seconds(monkeypatch):
    updated = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    class _Blob:
        def __init__(self):
            self.updated = updated

        def reload(self):
            return None

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud_storage, "_ensure_bucket", lambda: _Bucket())

    assert cloud_storage.blob_updated_timestamp("existing") == updated.timestamp()
