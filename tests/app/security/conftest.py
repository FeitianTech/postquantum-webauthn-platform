"""Fixtures for the ceremony-integrity security tests.

Only *storage* side effects are neutralised here. Every verification code path
-- challenge binding, origin checks, signature verification, attestation checks
-- runs for real in these tests, by design.
"""
from __future__ import annotations

from typing import Any

import pytest


@pytest.fixture
def config_module():
    return pytest.importorskip("server.app.config")


@pytest.fixture
def simple_module():
    pytest.importorskip("server.app.app")
    return pytest.importorskip("server.app.routes.simple")


@pytest.fixture
def advanced_module():
    pytest.importorskip("server.app.app")
    return pytest.importorskip("server.app.routes.advanced")


def _session_metadata_in(tmp_path, monkeypatch) -> None:
    # A ceremony creates the caller's metadata session directory.
    from server.app.storage import session_metadata

    monkeypatch.setattr(session_metadata, "SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))


@pytest.fixture
def simple_storage(simple_module, monkeypatch, tmp_path, device_logs_module, storage_module) -> dict[str, Any]:
    """Neutralise simple-flow persistence and capture what it would store."""

    _session_metadata_in(tmp_path, monkeypatch)
    saved: dict[str, Any] = {}

    def _save_if_unchanged(email, credentials, version, *, session_id=None):
        saved["email"] = email
        saved["credentials"] = credentials
        saved["session_id"] = session_id
        return True

    monkeypatch.setattr(storage_module, "save_if_unchanged", _save_if_unchanged)
    monkeypatch.setattr(storage_module, "read_for_update", lambda *_a, **_k: ([], None))
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)
    return saved


@pytest.fixture
def advanced_storage(advanced_module, monkeypatch, tmp_path, credential_artifacts_module, device_logs_module) -> list[Any]:
    """Neutralise advanced-flow persistence and capture stored artifacts."""

    _session_metadata_in(tmp_path, monkeypatch)
    stored: list[Any] = []

    def _store(storage_id, payload, *, session_id=None):
        stored.append((storage_id, payload, session_id))
        return True

    monkeypatch.setattr(credential_artifacts_module, "store_credential_artifact", _store)
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)
    return stored


@pytest.fixture
def allowed_origins(config_module, monkeypatch):
    """Set (and automatically restore) the exact-origin allowlist."""

    def _apply(value):
        monkeypatch.setitem(config_module.app.config, "FIDO_SERVER_ALLOWED_ORIGINS", value)

    return _apply
