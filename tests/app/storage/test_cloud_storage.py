"""Tests for the Google Cloud Storage helpers."""

from __future__ import annotations

import importlib
import types
from datetime import datetime, timezone

import pytest

cloud = importlib.import_module("server.app.storage.cloud")


RETRY = "the client's retry"


@pytest.fixture(autouse=True)
def _the_clients_retry(monkeypatch, request):
    if request.node.name != "test_every_call_is_given_the_client_librarys_retry_within_a_bound":
        monkeypatch.setattr(cloud, "_retry", lambda: RETRY)


def test_list_blob_names_passes_a_delimiter_only_when_asked(monkeypatch):
    calls = []

    class _Bucket:
        def list_blobs(self, **kwargs):
            calls.append(kwargs)
            return [types.SimpleNamespace(name="user-data/flat")]

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    assert list(cloud.list_blob_names("user-data/")) == ["user-data/flat"]
    assert list(cloud.list_blob_names("user-data/", delimiter="/")) == ["user-data/flat"]
    assert calls == [
        {"prefix": "user-data/", "retry": RETRY},
        {"prefix": "user-data/", "delimiter": "/", "retry": RETRY},
    ]


def test_download_bytes_handles_not_found(monkeypatch):
    class _Blob:
        def download_as_bytes(self, **_options):
            raise cloud._lazy("gcs_exceptions").NotFound("missing")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

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
        ("unexpected", None),
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
        def delete(self, retry=None):
            raise cloud._lazy("gcs_exceptions").NotFound("missing")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    with pytest.raises(cloud._lazy("gcs_exceptions").NotFound):
        cloud.delete_blob("missing", missing_ok=False)


def test_blob_exists_casts_result_to_bool(monkeypatch):
    class _Blob:
        def exists(self, retry=None):
            return "truthy"

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    assert cloud.blob_exists("any") is True


def test_blob_updated_timestamp_returns_none_when_blob_missing(monkeypatch):
    class _Blob:
        updated = None

        def reload(self, retry=None):
            raise cloud._lazy("gcs_exceptions").NotFound("missing")

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    assert cloud.blob_updated_timestamp("missing") is None


def test_blob_updated_timestamp_returns_none_when_updated_unset(monkeypatch):
    class _Blob:
        updated = None

        def reload(self, retry=None):
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

        def reload(self, retry=None):
            return None

    class _Bucket:
        def blob(self, _name):
            return _Blob()

    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: _Bucket())

    assert cloud.blob_updated_timestamp("existing") == updated.timestamp()


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
        def delete(self, retry=None):
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

    assert cloud.download_bytes_with_generation("mds/current.json", timeout=5, attempts=1) == (b"{}", 1)
    assert bucket.download_options[-1] == ("mds/current.json", {"timeout": 5, "retry": None})

    # Without a bound the client library's own retry is used.
    assert cloud.download_bytes_with_generation("mds/current.json") == (b"{}", 1)
    assert bucket.download_options[-1] == ("mds/current.json", {"retry": "the client's retry"})


def test_every_call_is_given_the_client_librarys_retry_within_a_bound(monkeypatch):
    """No loop of our own around the client's: its DEFAULT_RETRY, for 30 s at most."""

    monkeypatch.setattr(cloud, "_RETRY", None)
    retry = cloud._retry()
    storage_retry = importlib.import_module("google.cloud.storage.retry")

    assert retry._predicate is storage_retry.DEFAULT_RETRY._predicate
    assert retry._timeout == 30.0
    assert cloud._retry() is retry

