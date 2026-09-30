"""Tests for the server startup module."""

from __future__ import annotations


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


def test_env_flag_parses_false_values(monkeypatch):
    from server.app import startup

    monkeypatch.setenv("FIDO_SERVER_TEST_FLAG", "0")
    assert startup._env_flag("FIDO_SERVER_TEST_FLAG") is False
