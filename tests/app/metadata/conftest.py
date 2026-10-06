"""Fixtures for the MDS tests."""

from __future__ import annotations

import pytest

from server.app import visitor_session
from server.app.storage import cloud as storage_cloud
from server.app.storage import common as storage_common
from tests.app.entry_app import entry_app


@pytest.fixture
def visitor(monkeypatch, tmp_path, metadata_state, make_app):
    """A request whose visitor can upload metadata into a store of this test's."""

    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))
    monkeypatch.setattr(visitor_session, "schedule_cleanup", lambda: None)
    with make_app().test_request_context("/"):
        yield


@pytest.fixture
def metadata_local_env(monkeypatch, tmp_path, metadata_state):
    session_dir = tmp_path / "session-metadata"
    session_dir.mkdir()

    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(session_dir))

    monkeypatch.setattr(storage_cloud, "gcs_enabled", lambda: False)
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)


    return entry_app()
