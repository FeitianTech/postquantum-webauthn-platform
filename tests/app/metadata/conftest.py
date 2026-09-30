"""Shared fixtures for the metadata runtime tests."""

from __future__ import annotations

import importlib
import shutil

import pytest

from server.app.webauthn.metadata import blob as metadata_blob
from server.app.webauthn.metadata import state

# The inactive-session cleanup's state, with the value each holds on a freshly
# imported module.
_CLEANUP_STATE_DEFAULTS = {
    "_session_metadata_last_cleanup": 0.0,
    "_session_cleanup_worker": None,
    "_session_cleanup_pending": False,
}


@pytest.fixture
def metadata_state(monkeypatch):
    """A fresh snapshot cache and cleanup state for the duration of one test.

    ``raising`` is deliberately left at its default. These names moved here from
    ``server.app.webauthn.metadata`` once already; if one moves again, the patch must fail
    loudly rather than quietly resetting nothing and leaving the test to pass
    while exercising stale state.
    """

    monkeypatch.setattr(metadata_blob, "CACHE", metadata_blob.SnapshotCache())
    for name, default in _CLEANUP_STATE_DEFAULTS.items():
        monkeypatch.setattr(state, name, default)
    return state


@pytest.fixture
def sessions():
    """The fragment that defines the session identity helpers. Patch here rather than on ``server.app.webauthn.metadata``: the other fragments call these through this module, so this is the binding that is actually read. The fragment that defines the session metadata item helpers. The fragment that defines the session cleanup worker and scheduler."""

    return importlib.import_module("server.app.webauthn.metadata.sessions")


@pytest.fixture
def entries():
    """The fragment that defines the entry payload helpers."""

    return importlib.import_module("server.app.webauthn.metadata.entries")


@pytest.fixture
def blob():
    """The fragment that defines the base/explorer/full snapshot loaders. The fragment that defines the metadata cache helpers."""

    return importlib.import_module("server.app.webauthn.metadata.blob")


@pytest.fixture
def uploads():
    """The fragment that defines the repository upload helpers."""

    return importlib.import_module("server.app.webauthn.metadata.uploads")


@pytest.fixture
def effective():
    """The fragment that composes base and session snapshots."""

    return importlib.import_module("server.app.webauthn.metadata.effective")


@pytest.fixture
def session_store():
    """The storage module the metadata fragments write through."""

    return importlib.import_module("server.app.storage.session_metadata")


@pytest.fixture
def app_config():
    """The app config module, for the Flask app and its logger."""

    return importlib.import_module("server.app.config")


@pytest.fixture
def verifier():
    """The fragment that defines the metadata merge and verifier helpers."""

    return importlib.import_module("server.app.webauthn.metadata.verifier")


@pytest.fixture
def mds_fixture_snapshot(monkeypatch, tmp_path, metadata_state):
    """The fixture snapshot (tests/fixtures/mds/snapshot), copied into this test's
    directory and made the snapshot directory. Copied, never served in place, so
    nothing a test does lands in the checkout; with fresh modification times,
    since the metadata caches key on them."""

    from tests.app.metadata import mds_fixture

    target = tmp_path / "mds-snapshot"
    shutil.copytree(mds_fixture.SNAPSHOT_DIR, target, copy_function=shutil.copy)
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(target))
    return target
