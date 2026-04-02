"""Tests for the server startup module."""

from __future__ import annotations

import importlib
import os
import sys
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

# Setup module structure
server_pkg = types.ModuleType("server")
server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", server_pkg)

server_server_pkg = types.ModuleType("server.server")
server_server_pkg.__path__ = [str(_ROOT / "server" / "server")]
sys.modules.setdefault("server.server", server_server_pkg)


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
    
    from server.server import startup, cloud_storage
    
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: False)
    
    assert startup._should_warm_cloud_storage() is False


def test_should_warm_cloud_storage_no_bucket(monkeypatch):
    """Test that cloud storage warming is disabled when no bucket is set."""
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    
    from server.server import startup, cloud_storage
    
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: True)
    
    assert startup._should_warm_cloud_storage() is False


def test_should_warm_cloud_storage_enabled(monkeypatch):
    """Test that cloud storage warming is enabled when GCS is configured."""
    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "test-bucket")
    
    from server.server import startup, cloud_storage
    
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: True)
    
    assert startup._should_warm_cloud_storage() is True


def test_startup_fail_fast_defaults_to_fast(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_STARTUP_MODE", raising=False)
    monkeypatch.delenv("FIDO_SERVER_STARTUP_FAIL_FAST", raising=False)

    from server.server import startup

    assert startup.startup_fail_fast_enabled() is False


def test_startup_fail_fast_honors_strict_mode(monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_STARTUP_MODE", "strict")
    monkeypatch.delenv("FIDO_SERVER_STARTUP_FAIL_FAST", raising=False)

    from server.server import startup

    assert startup.startup_fail_fast_enabled() is True


def test_warm_up_dependencies_success(monkeypatch):
    """Test successful startup dependency warming."""
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    
    from server.server import startup, cloud_storage, session_metadata_store
    
    # Mock all dependencies
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: False)
    
    metadata_bootstrapped = []
    def mock_bootstrap(**kwargs):
        metadata_bootstrapped.append(kwargs)
    
    # Create a mock for ensure_metadata_bootstrapped
    general_routes = types.ModuleType("server.server.routes.general")
    general_routes.ensure_metadata_bootstrapped = mock_bootstrap
    monkeypatch.setitem(sys.modules, "server.server.routes.general", general_routes)
    
    session_ops = []
    monkeypatch.setattr(
        session_metadata_store,
        "ensure_session",
        lambda sid: session_ops.append(("ensure", sid))
    )
    monkeypatch.setattr(
        session_metadata_store,
        "touch_last_access",
        lambda sid: session_ops.append(("touch", sid))
    )
    monkeypatch.setattr(
        session_metadata_store,
        "delete_session",
        lambda sid: session_ops.append(("delete", sid))
    )
    
    # Run startup
    startup.warm_up_dependencies(fail_fast=True)
    
    # Verify metadata was bootstrapped
    assert len(metadata_bootstrapped) == 1
    
    # Verify session operations
    assert ("ensure", "__startup__") in session_ops
    assert ("touch", "__startup__") in session_ops
    assert ("delete", "__startup__") in session_ops


def test_warm_up_dependencies_with_gcs(monkeypatch):
    """Test startup with cloud storage warming."""
    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "test-bucket")
    
    from server.server import startup, cloud_storage, session_metadata_store
    
    # Mock dependencies
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: True)
    
    gcs_ready = []
    monkeypatch.setattr(cloud_storage, "ensure_ready", lambda: gcs_ready.append(True))
    
    # Mock metadata bootstrap
    general_routes = types.ModuleType("server.server.routes.general")
    general_routes.ensure_metadata_bootstrapped = lambda **kwargs: None
    monkeypatch.setitem(sys.modules, "server.server.routes.general", general_routes)
    
    monkeypatch.setattr(session_metadata_store, "ensure_session", lambda sid: None)
    monkeypatch.setattr(session_metadata_store, "touch_last_access", lambda sid: None)
    monkeypatch.setattr(session_metadata_store, "delete_session", lambda sid: None)
    
    # Run startup
    startup.warm_up_dependencies(fail_fast=True)
    
    # Verify GCS was checked
    assert gcs_ready == [True]


def test_warm_up_dependencies_metadata_bootstrap_failure(monkeypatch):
    """Test startup failure during metadata bootstrap."""
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    
    from server.server import startup
    
    # Mock metadata bootstrap to fail
    general_routes = types.ModuleType("server.server.routes.general")
    general_routes.ensure_metadata_bootstrapped = lambda **kwargs: (_ for _ in ()).throw(
        RuntimeError("Bootstrap failed")
    )
    monkeypatch.setitem(sys.modules, "server.server.routes.general", general_routes)
    
    # Verify exception is raised
    with pytest.raises(RuntimeError, match="Bootstrap failed"):
        startup.warm_up_dependencies(fail_fast=True)


def test_warm_up_dependencies_gcs_failure(monkeypatch):
    """Test startup failure during GCS check."""
    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "test-bucket")
    
    from server.server import startup, cloud_storage
    
    # Mock GCS to fail
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: True)
    monkeypatch.setattr(
        cloud_storage,
        "ensure_ready",
        lambda: (_ for _ in ()).throw(RuntimeError("GCS failed"))
    )
    
    # Mock metadata bootstrap
    general_routes = types.ModuleType("server.server.routes.general")
    general_routes.ensure_metadata_bootstrapped = lambda **kwargs: None
    monkeypatch.setitem(sys.modules, "server.server.routes.general", general_routes)
    
    # Verify exception is raised
    with pytest.raises(RuntimeError, match="GCS failed"):
        startup.warm_up_dependencies(fail_fast=True)


def test_warm_up_dependencies_session_storage_failure(monkeypatch):
    """Test startup failure during session storage check."""
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    
    from server.server import startup, cloud_storage, session_metadata_store
    
    # Mock dependencies
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: False)
    
    # Mock metadata bootstrap
    general_routes = types.ModuleType("server.server.routes.general")
    general_routes.ensure_metadata_bootstrapped = lambda **kwargs: None
    monkeypatch.setitem(sys.modules, "server.server.routes.general", general_routes)
    
    # Mock session storage to fail
    monkeypatch.setattr(
        session_metadata_store,
        "ensure_session",
        lambda sid: (_ for _ in ()).throw(RuntimeError("Storage failed"))
    )
    
    # Verify exception is raised
    with pytest.raises(RuntimeError, match="Storage failed"):
        startup.warm_up_dependencies(fail_fast=True)


def test_warm_up_dependencies_cleanup_on_success(monkeypatch):
    """Test that startup session is cleaned up on success."""
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    
    from server.server import startup, cloud_storage, session_metadata_store
    
    # Mock dependencies
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: False)
    
    # Mock metadata bootstrap
    general_routes = types.ModuleType("server.server.routes.general")
    general_routes.ensure_metadata_bootstrapped = lambda **kwargs: None
    monkeypatch.setitem(sys.modules, "server.server.routes.general", general_routes)
    
    deleted_sessions = []
    monkeypatch.setattr(session_metadata_store, "ensure_session", lambda sid: None)
    monkeypatch.setattr(session_metadata_store, "touch_last_access", lambda sid: None)
    monkeypatch.setattr(
        session_metadata_store,
        "delete_session",
        lambda sid: deleted_sessions.append(sid)
    )
    
    # Run startup
    startup.warm_up_dependencies(fail_fast=True)
    
    # Verify cleanup happened
    assert "__startup__" in deleted_sessions


def test_warm_up_dependencies_cleanup_on_failure(monkeypatch):
    """Test that startup session cleanup is attempted even on failure."""
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    
    from server.server import startup, cloud_storage, session_metadata_store
    
    # Mock dependencies
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: False)
    
    # Mock metadata bootstrap
    general_routes = types.ModuleType("server.server.routes.general")
    general_routes.ensure_metadata_bootstrapped = lambda **kwargs: None
    monkeypatch.setitem(sys.modules, "server.server.routes.general", general_routes)
    
    deleted_sessions = []
    monkeypatch.setattr(session_metadata_store, "ensure_session", lambda sid: None)
    monkeypatch.setattr(session_metadata_store, "touch_last_access", lambda sid: None)
    monkeypatch.setattr(
        session_metadata_store,
        "delete_session",
        lambda sid: deleted_sessions.append(sid)
    )
    
    # Make session touch fail
    monkeypatch.setattr(
        session_metadata_store,
        "touch_last_access",
        lambda sid: (_ for _ in ()).throw(RuntimeError("Storage failed"))
    )
    
    # Verify exception is raised but cleanup still happens
    with pytest.raises(RuntimeError, match="Storage failed"):
        startup.warm_up_dependencies(fail_fast=True)
    
    assert "__startup__" in deleted_sessions


def test_warm_up_dependencies_skip_if_reloader_parent(monkeypatch):
    """Test that reloader parent flag is passed to metadata bootstrap."""
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    
    from server.server import startup, cloud_storage, session_metadata_store
    
    # Mock dependencies
    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: False)
    
    bootstrap_calls = []
    general_routes = types.ModuleType("server.server.routes.general")
    general_routes.ensure_metadata_bootstrapped = lambda **kwargs: bootstrap_calls.append(kwargs)
    monkeypatch.setitem(sys.modules, "server.server.routes.general", general_routes)
    
    monkeypatch.setattr(session_metadata_store, "ensure_session", lambda sid: None)
    monkeypatch.setattr(session_metadata_store, "touch_last_access", lambda sid: None)
    monkeypatch.setattr(session_metadata_store, "delete_session", lambda sid: None)
    
    # Run startup with skip flag
    startup.warm_up_dependencies(skip_if_reloader_parent=True, fail_fast=True)
    
    # Verify flag was passed
    assert bootstrap_calls == [{"skip_if_reloader_parent": True}]


def test_warm_up_dependencies_fast_mode_skips_heavy_checks(monkeypatch):
    """Fast startup mode should skip eager warmups by default."""

    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "test-bucket")

    from server.server import startup, cloud_storage, session_metadata_store

    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: True)

    bootstrap_calls = []
    gcs_calls = []
    session_calls = []

    general_routes = types.ModuleType("server.server.routes.general")
    general_routes.ensure_metadata_bootstrapped = lambda **kwargs: bootstrap_calls.append(kwargs)
    monkeypatch.setitem(sys.modules, "server.server.routes.general", general_routes)

    monkeypatch.setattr(cloud_storage, "ensure_ready", lambda: gcs_calls.append(True))
    monkeypatch.setattr(session_metadata_store, "ensure_session", lambda sid: session_calls.append(("ensure", sid)))
    monkeypatch.setattr(session_metadata_store, "touch_last_access", lambda sid: session_calls.append(("touch", sid)))

    startup.warm_up_dependencies(fail_fast=False)

    assert bootstrap_calls == []
    assert gcs_calls == []
    assert session_calls == []


def test_warm_up_dependencies_fast_mode_does_not_raise(monkeypatch):
    """Fast startup mode should log failures without raising."""

    monkeypatch.setenv("FIDO_SERVER_WARM_SESSION_STORAGE", "1")
    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)

    from server.server import startup, cloud_storage, session_metadata_store

    monkeypatch.setattr(cloud_storage, "gcs_enabled", lambda: False)
    monkeypatch.setattr(
        session_metadata_store,
        "ensure_session",
        lambda sid: (_ for _ in ()).throw(RuntimeError("session warm failed")),
    )

    startup.warm_up_dependencies(fail_fast=False)
