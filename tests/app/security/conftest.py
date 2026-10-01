"""Fixtures for the ceremony-integrity security tests.

Only *storage* side effects are neutralised here. Every verification code path
-- challenge binding, origin checks, signature verification, attestation checks
-- runs for real in these tests, by design.
"""
from __future__ import annotations

from typing import Any

import pytest

from server.app.storage import credential_artifacts, github_mirror
from server.app.storage import credentials as storage_credentials
from tests.app.entry_app import entry_app


def _session_metadata_in(tmp_path, monkeypatch) -> None:
    # A ceremony creates the caller's metadata session directory.

    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))


@pytest.fixture
def simple_storage(monkeypatch, tmp_path) -> dict[str, Any]:
    """Neutralise simple-flow persistence and capture what it would store."""

    _session_metadata_in(tmp_path, monkeypatch)
    saved: dict[str, Any] = {}

    def _save_if_unchanged(email, credentials, version, *, session_id=None):
        saved["email"] = email
        saved["credentials"] = credentials
        saved["session_id"] = session_id
        return True

    monkeypatch.setattr(storage_credentials, "save_if_unchanged", _save_if_unchanged)
    monkeypatch.setattr(storage_credentials, "read_for_update", lambda *_a, **_k: ([], None))
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda _event: None)
    return saved


@pytest.fixture
def advanced_storage(monkeypatch, tmp_path) -> list[Any]:
    """Neutralise advanced-flow persistence and capture stored artifacts."""

    _session_metadata_in(tmp_path, monkeypatch)
    stored: list[Any] = []

    def _store(storage_id, payload, *, session_id=None):
        stored.append((storage_id, payload, session_id))
        return True

    monkeypatch.setattr(credential_artifacts, "store_credential_artifact", _store)
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda _event: None)
    return stored


@pytest.fixture
def allowed_origins(monkeypatch):
    """Set (and automatically restore) the exact-origin allowlist."""

    def _apply(value):
        monkeypatch.setitem(entry_app().config, "FIDO_SERVER_ALLOWED_ORIGINS", value)

    return _apply
