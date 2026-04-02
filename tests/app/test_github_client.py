"""Tests for the GitHub client module."""
import sys
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]

server_pkg = types.ModuleType("server")
server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", server_pkg)

server_server_pkg = types.ModuleType("server.app")
server_server_pkg.__path__ = [str(_ROOT / "server" / "app")]
sys.modules.setdefault("server.app", server_server_pkg)

from server.app import github_client
from server.app.github_client import is_logging_enabled


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


def test_api_url_uses_default_log_repository(monkeypatch):
    monkeypatch.delenv("GITHUB_LOG_REPO_OWNER", raising=False)
    monkeypatch.delenv("GITHUB_LOG_REPO_NAME", raising=False)

    assert github_client._api_url("contents/logs/example.json") == (
        "https://api.github.com/repos/rainzhang05/CredentialLogs/contents/logs/example.json"
    )


def test_api_url_uses_repo_env_override(monkeypatch):
    monkeypatch.setenv("GITHUB_LOG_REPO_OWNER", "example-owner")
    monkeypatch.setenv("GITHUB_LOG_REPO_NAME", "example-repo")

    assert github_client._api_url("contents/logs/example.json") == (
        "https://api.github.com/repos/example-owner/example-repo/contents/logs/example.json"
    )
