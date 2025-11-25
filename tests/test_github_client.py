"""Tests for the GitHub client module."""
import pytest

from server.server.github_client import is_logging_enabled


def test_is_logging_enabled_default(monkeypatch):
    """Test that logging is enabled by default when no env vars are set."""
    monkeypatch.delenv("ENABLE_GITHUB_LOGGING", raising=False)
    assert is_logging_enabled() is True


def test_is_logging_enabled_explicit_true(monkeypatch):
    """Test that logging is enabled when ENABLE_GITHUB_LOGGING is truthy."""
    for value in ("1", "true", "yes", "on", "True", "YES", "ON"):
        monkeypatch.setenv("ENABLE_GITHUB_LOGGING", value)
        assert is_logging_enabled() is True, f"Expected True for value '{value}'"


def test_is_logging_enabled_explicit_false(monkeypatch):
    """Test that logging is disabled when ENABLE_GITHUB_LOGGING is falsy."""
    for value in ("0", "false", "no", "off", "False", "NO", "OFF"):
        monkeypatch.setenv("ENABLE_GITHUB_LOGGING", value)
        assert is_logging_enabled() is False, f"Expected False for value '{value}'"


def test_is_logging_enabled_empty_string(monkeypatch):
    """Test that logging is disabled when ENABLE_GITHUB_LOGGING is an empty string."""
    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "")
    assert is_logging_enabled() is False
