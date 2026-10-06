"""Tests of common behavior."""

import os

from server.app.storage import cloud as storage_cloud
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


def test_using_gcs_depends_on_flag_and_bucket(monkeypatch):
    monkeypatch.setattr(storage_cloud, "gcs_enabled", lambda: True)
    monkeypatch.setenv("FIDO_SERVER_GCS_BUCKET", "bucket-a")
    assert storage_common.using_gcs() is True

    monkeypatch.delenv("FIDO_SERVER_GCS_BUCKET", raising=False)
    assert storage_common.using_gcs() is False
