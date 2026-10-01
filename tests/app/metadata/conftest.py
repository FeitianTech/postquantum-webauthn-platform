"""Fixtures for the MDS tests."""

from __future__ import annotations

import pytest

from server.app import visitor_session


@pytest.fixture
def visitor(monkeypatch, tmp_path, metadata_state, make_app):
    """A request whose visitor can upload metadata into a store of this test's."""

    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))
    monkeypatch.setattr(visitor_session, "schedule_cleanup", lambda: None)
    with make_app().test_request_context("/"):
        yield
