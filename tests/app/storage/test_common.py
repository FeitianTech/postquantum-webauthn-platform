"""Tests of common behavior."""

import os

from server.app.storage import common as storage_common


def test_normalise_session_identifier_rejects_path_separators(monkeypatch):
    assert storage_common.normalise_session_id("session/abc") is None

    monkeypatch.setattr(os, "altsep", "\\")
    assert storage_common.normalise_session_id("session\\abc") is None


def test_normalise_session_identifier_accepts_clean_value_and_rejects_invalid_shapes():
    assert (
        storage_common.normalise_session_id(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        == "550e8400-e29b-41d4-a716-446655440000"
    )
    assert storage_common.normalise_session_id("  session-1  ") == "session-1"
    assert storage_common.normalise_session_id("   ") is None
    assert storage_common.normalise_session_id(".hidden") is None
    assert storage_common.normalise_session_id(123) is None
