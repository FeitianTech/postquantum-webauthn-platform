"""Fixtures the storage tests share."""
from __future__ import annotations

import pytest

from server.app.storage import common as storage_common


@pytest.fixture
def artifacts_on_disk(monkeypatch, tmp_path):
    """The credential artifact store in this test's folder, on disk."""

    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)
    return tmp_path
