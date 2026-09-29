"""Tests for the Google Cloud Storage helpers."""

from __future__ import annotations

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
cloud = importlib.import_module("server.app.storage.cloud")


def test_with_retry_succeeds_after_transient_error(monkeypatch):
    attempts = {"count": 0}

    class _Blob:
        def upload_from_string(self, *_args, **_kwargs):
            attempts["count"] += 1
            if attempts["count"] < 2:
                raise cloud._lazy("gcs_exceptions").GoogleAPICallError("retry")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    sleeps = []
    monkeypatch.setattr(cloud.time, "sleep", lambda delay: sleeps.append(delay))

    cloud.upload_bytes("test", b"data")

    assert attempts["count"] == 2
    assert sleeps == [cloud._DEFAULT_RETRY_BASE_DELAY]


def test_with_retry_raises_after_exhausting_attempts(monkeypatch):
    class _Blob:
        def upload_from_string(self, *_args, **_kwargs):
            raise cloud._lazy("gcs_exceptions").GoogleAPICallError("fail")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())
    monkeypatch.setattr(cloud.time, "sleep", lambda _delay: None)

    with pytest.raises(cloud._lazy("gcs_exceptions").GoogleAPICallError):
        cloud.upload_bytes("test", b"data")


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
                        raise cloud._lazy("gcs_exceptions").RetryError("transient")

                return _Iterator()
            return [types.SimpleNamespace(name="one"), types.SimpleNamespace(name="two")]

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())
    monkeypatch.setattr(cloud.time, "sleep", lambda _delay: None)

    names = list(cloud.list_blob_names("prefix"))

    assert names == ["one", "two"]
    assert call_state["attempt"] == 2


def test_list_blob_names_passes_a_delimiter_only_when_asked(monkeypatch):
    calls = []

    class _Bucket:
        def list_blobs(self, **kwargs):
            calls.append(kwargs)
            return [types.SimpleNamespace(name="user-data/flat")]

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    assert list(cloud.list_blob_names("user-data/")) == ["user-data/flat"]
    assert list(cloud.list_blob_names("user-data/", delimiter="/")) == ["user-data/flat"]
    assert calls == [{"prefix": "user-data/"}, {"prefix": "user-data/", "delimiter": "/"}]


def test_download_bytes_handles_not_found(monkeypatch):
    class _Blob:
        def download_as_bytes(self):
            raise cloud._lazy("gcs_exceptions").NotFound("missing")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())
    monkeypatch.setattr(cloud.time, "sleep", lambda _delay: None)

    assert cloud.download_bytes("missing") is None


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

    assert cloud._env_flag("TEST_FLAG") is expected


def test_gcs_enabled_defaults_to_false_when_env_missing(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)

    assert cloud.gcs_enabled() is False


def test_gcs_enabled_honors_explicit_true_false(monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_GCS_ENABLED", "1")
    assert cloud.gcs_enabled() is True

    monkeypatch.setenv("FIDO_SERVER_GCS_ENABLED", "false")
    assert cloud.gcs_enabled() is False


def test_build_client_uses_the_project_setting(monkeypatch):
    observed = {}

    monkeypatch.setenv("FIDO_SERVER_GCS_PROJECT", "override-only")

    def _client_factory(*args, **kwargs):
        observed["args"] = args
        observed["kwargs"] = kwargs
        return "project-client"

    monkeypatch.setattr(cloud._lazy("storage"), "Client", _client_factory)

    assert cloud._build_client() == "project-client"
    assert observed["args"] == ()
    assert observed["kwargs"] == {"project": "override-only"}


def test_build_client_defaults_to_storage_client_without_overrides(monkeypatch):
    observed = {}

    monkeypatch.delenv("FIDO_SERVER_GCS_PROJECT", raising=False)

    def _client_factory(*args, **kwargs):
        observed["args"] = args
        observed["kwargs"] = kwargs
        return "default-client"

    monkeypatch.setattr(cloud._lazy("storage"), "Client", _client_factory)

    assert cloud._build_client() == "default-client"
    assert observed["args"] == ()
    assert observed["kwargs"] == {"project": None}


def test_ensure_bucket_raises_when_gcs_disabled(monkeypatch):
    monkeypatch.setattr(cloud, "_CLIENT", None)
    monkeypatch.setattr(cloud, "_BUCKET", None)
    monkeypatch.setattr(cloud, "gcs_enabled", lambda: False)

    with pytest.raises(RuntimeError, match="disabled"):
        cloud._ensure_bucket()


def test_ensure_bucket_requires_bucket_configuration(monkeypatch):
    monkeypatch.setattr(cloud, "_CLIENT", None)
    monkeypatch.setattr(cloud, "_BUCKET", None)
    monkeypatch.setattr(cloud, "gcs_enabled", lambda: True)
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)

    with pytest.raises(RuntimeError, match="FIDO_SERVER_GCS_BUCKET"):
        cloud._ensure_bucket()


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

    monkeypatch.setattr(cloud, "_CLIENT", None)
    monkeypatch.setattr(cloud, "_BUCKET", None)
    monkeypatch.setattr(cloud, "gcs_enabled", lambda: True)
    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "cache-bucket")
    monkeypatch.setattr(cloud, "_build_client", _build_client)

    first = cloud._ensure_bucket()
    second = cloud._ensure_bucket()

    assert first is bucket_value
    assert second is bucket_value
    assert build_calls["count"] == 1
    assert bucket_calls["count"] == 1


def test_with_retry_does_not_retry_not_found(monkeypatch):
    calls = {"count": 0}
    sleeps = []

    def _operation():
        calls["count"] += 1
        raise cloud._lazy("gcs_exceptions").NotFound("missing")

    monkeypatch.setattr(cloud.time, "sleep", lambda delay: sleeps.append(delay))

    with pytest.raises(cloud._lazy("gcs_exceptions").NotFound):
        cloud._with_retry(_operation)

    assert calls["count"] == 1
    assert sleeps == []


def test_with_retry_uses_exponential_backoff(monkeypatch):
    calls = {"count": 0}
    sleeps = []

    def _operation():
        calls["count"] += 1
        if calls["count"] < 3:
            raise cloud._lazy("gcs_exceptions").GoogleAPICallError("transient")
        return "ok"

    monkeypatch.setattr(cloud.time, "sleep", lambda delay: sleeps.append(delay))

    result = cloud._with_retry(_operation)

    assert result == "ok"
    assert sleeps == [0.5, 1.0]


def test_build_blob_name_normalizes_components_and_prefix():
    blob = cloud.build_blob_name(
        "/session-id/",
        "/credentials/",
        "file.pkl",
        prefix=" /user-data/ ",
    )

    assert blob == "user-data/session-id/credentials/file.pkl"


def test_build_blob_name_raises_for_empty_path_components():
    with pytest.raises(ValueError, match="Invalid blob path components"):
        cloud.build_blob_name("", "/", prefix="/prefix/")


def test_delete_blob_honors_missing_ok_false(monkeypatch):
    class _Blob:
        def delete(self):
            raise cloud._lazy("gcs_exceptions").NotFound("missing")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    with pytest.raises(cloud._lazy("gcs_exceptions").NotFound):
        cloud.delete_blob("missing", missing_ok=False)


def test_blob_exists_casts_result_to_bool(monkeypatch):
    class _Blob:
        def exists(self):
            return "truthy"

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    assert cloud.blob_exists("any") is True


def test_blob_updated_timestamp_returns_none_when_blob_missing(monkeypatch):
    class _Blob:
        updated = None

        def reload(self):
            raise cloud._lazy("gcs_exceptions").NotFound("missing")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    assert cloud.blob_updated_timestamp("missing") is None


def test_blob_updated_timestamp_returns_none_when_updated_unset(monkeypatch):
    class _Blob:
        updated = None

        def reload(self):
            return None

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    assert cloud.blob_updated_timestamp("existing") is None


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

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    assert cloud.blob_updated_timestamp("existing") == updated.timestamp()


def test_with_retry_raises_runtime_when_no_attempts_configured():
    with pytest.raises(RuntimeError, match="failed without raising"):
        cloud._with_retry(lambda: "ok", max_attempts=0)


def test_normalise_prefix_handles_empty_inputs():
    assert cloud.normalise_blob_prefix(None) == ""
    assert cloud.normalise_blob_prefix("///") == ""


def test_ensure_bucket_reuses_existing_client(monkeypatch):
    calls = {"bucket": 0}
    expected_bucket = object()

    class _Client:
        def bucket(self, name):
            calls["bucket"] += 1
            assert name == "configured-bucket"
            return expected_bucket

    monkeypatch.setattr(cloud, "_CLIENT", _Client())
    monkeypatch.setattr(cloud, "_BUCKET", None)
    monkeypatch.setattr(cloud, "gcs_enabled", lambda: True)
    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "configured-bucket")
    monkeypatch.setattr(
        cloud,
        "_build_client",
        lambda: (_ for _ in ()).throw(AssertionError("_build_client should not be called")),
    )

    bucket = cloud._ensure_bucket()

    assert bucket is expected_bucket
    assert calls["bucket"] == 1


def test_delete_blob_ignores_not_found_when_missing_ok_true(monkeypatch):
    class _Blob:
        def delete(self):
            raise cloud._lazy("gcs_exceptions").NotFound("missing")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    cloud.delete_blob("missing", missing_ok=True)


def test_a_download_can_be_bounded_to_one_short_attempt(monkeypatch):
    from tests.app.storage import fake_gcs

    bucket = fake_gcs.install(monkeypatch)
    bucket.put("mds/current.json", b"{}")
    slept = []
    monkeypatch.setattr(cloud.time, "sleep", slept.append)

    assert cloud.download_bytes_with_generation("mds/current.json", timeout=5, attempts=1) == (b"{}", 1)
    assert bucket.download_options[-1] == ("mds/current.json", {"timeout": 5, "retry": None})

    # A transient failure is not retried: the caller hears of it at once.
    bucket.failing["mds/current.json"] = OSError("unavailable")
    with pytest.raises(OSError):
        cloud.download_bytes_with_generation("mds/current.json", timeout=5, attempts=1)
    assert slept == []

    # The default keeps the client's own retry and the three attempts.
    with pytest.raises(OSError):
        cloud.download_bytes_with_generation("mds/current.json")
    assert bucket.download_options[-1] == ("mds/current.json", {})
    assert len(slept) == 2
