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


@pytest.fixture
def simple_storage(simple_module, monkeypatch, device_logs_module) -> dict[str, Any]:
    """Neutralise simple-flow persistence and capture what it would store."""

    saved: dict[str, Any] = {}

    def _savekey(email, credentials, *, session_id=None):
        saved["email"] = email
        saved["credentials"] = credentials
        saved["session_id"] = session_id

    monkeypatch.setattr(simple_module, "savekey", _savekey)
    monkeypatch.setattr(simple_module, "readkey", lambda *_a, **_k: [])
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)
    return saved


@pytest.fixture
def advanced_storage(advanced_module, monkeypatch, credential_artifacts_module, device_logs_module) -> list[Any]:
    """Neutralise advanced-flow persistence and capture stored artifacts."""

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
