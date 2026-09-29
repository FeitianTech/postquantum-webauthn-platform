"""Tests for the server startup module."""

from __future__ import annotations

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

# Setup module structure
server_pkg = types.ModuleType("server")
server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", server_pkg)

server_server_pkg = types.ModuleType("server.app")
server_server_pkg.__path__ = [str(_ROOT / "server" / "app")]
sys.modules.setdefault("server.app", server_server_pkg)


@pytest.fixture(autouse=True)
def _mock_dependencies(monkeypatch):
    """Mock Google Cloud Storage dependencies for all tests."""
    # Setup google.api_core
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
        def bucket(self, *_args, **_kwargs):
            raise RuntimeError("Not configured")

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

    google_auth_pkg = types.ModuleType("google.auth")
    google_auth_pkg.__path__ = []
    sys.modules.setdefault("google.auth", google_auth_pkg)

    google_auth_exceptions_pkg = types.ModuleType("google.auth.exceptions")
    setattr(google_auth_exceptions_pkg, "RefreshError", Exception)
    sys.modules.setdefault("google.auth.exceptions", google_auth_exceptions_pkg)

    google_pkg.api_core = google_api_core_pkg
    google_pkg.cloud = google_cloud_pkg
    google_pkg.oauth2 = google_oauth_pkg
    google_api_core_pkg.exceptions = google_api_core_exceptions_pkg
    google_cloud_pkg.storage = google_cloud_storage_pkg
    google_oauth_pkg.service_account = google_service_account_pkg
    google_auth_pkg.exceptions = google_auth_exceptions_pkg


def test_should_warm_cloud_storage_disabled(monkeypatch):
    """Test that cloud storage warming is disabled when GCS is disabled."""
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    
    from server.app import startup
    from server.app.storage import cloud
    
    monkeypatch.setattr(cloud, "gcs_enabled", lambda: False)
    
    assert startup._should_warm_cloud_storage_configured() is False


def test_should_warm_cloud_storage_no_bucket(monkeypatch):
    """Test that cloud storage warming is disabled when no bucket is set."""
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    
    from server.app import startup
    from server.app.storage import cloud
    
    monkeypatch.setattr(cloud, "gcs_enabled", lambda: True)
    
    assert startup._should_warm_cloud_storage_configured() is False


def test_should_warm_cloud_storage_enabled(monkeypatch):
    """Test that cloud storage warming is enabled when GCS is configured."""
    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "test-bucket")
    
    from server.app import startup
    from server.app.storage import cloud
    
    monkeypatch.setattr(cloud, "gcs_enabled", lambda: True)
    
    assert startup._should_warm_cloud_storage_configured() is True


def test_startup_fail_fast_defaults_to_fast(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_STARTUP_MODE", raising=False)
    monkeypatch.delenv("FIDO_SERVER_STARTUP_FAIL_FAST", raising=False)

    from server.app import startup

    assert startup.startup_fail_fast_enabled() is False


def test_startup_fail_fast_honors_strict_mode(monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_STARTUP_MODE", "strict")
    monkeypatch.delenv("FIDO_SERVER_STARTUP_FAIL_FAST", raising=False)

    from server.app import startup

    assert startup.startup_fail_fast_enabled() is True


def test_env_flag_parses_false_values(monkeypatch):
    from server.app import startup

    monkeypatch.setenv("FIDO_SERVER_TEST_FLAG", "0")
    assert startup._env_flag("FIDO_SERVER_TEST_FLAG") is False


def test_startup_fail_fast_honors_explicit_env_override(monkeypatch):
    from server.app import startup

    monkeypatch.setenv("FIDO_SERVER_STARTUP_FAIL_FAST", "false")
    monkeypatch.setenv("FIDO_SERVER_STARTUP_MODE", "strict")

    assert startup.startup_fail_fast_enabled() is False


def test_startup_fail_fast_honors_non_blocking_mode(monkeypatch):
    from server.app import startup

    monkeypatch.delenv("FIDO_SERVER_STARTUP_FAIL_FAST", raising=False)
    monkeypatch.setenv("FIDO_SERVER_STARTUP_MODE", "non-blocking")

    assert startup.startup_fail_fast_enabled() is False
