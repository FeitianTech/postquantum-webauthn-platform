"""Fixtures for the advanced route tests."""
from __future__ import annotations

import pytest

from server.app.storage import github_mirror


@pytest.fixture
def advanced_stores(monkeypatch, tmp_path):
    """The real stores, in this test's directory; no registration is mirrored to GitHub."""

    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR", str(tmp_path / "credential-artifacts"))
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(tmp_path / "session-credentials"))
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda _event: None)
