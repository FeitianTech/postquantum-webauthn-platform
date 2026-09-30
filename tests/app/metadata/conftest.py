"""Shared fixtures for the metadata runtime tests."""

from __future__ import annotations

import importlib
import shutil

import pytest

from server.app import visitor_session
from server.app.mds import cache as mds_cache


@pytest.fixture
def metadata_state(monkeypatch):
    """A fresh snapshot cache and cleanup state for the duration of one test.

    ``raising`` is deliberately left at its default: if either name moves, the patch
    must fail loudly rather than quietly resetting nothing and leaving the test to
    pass while exercising stale state.
    """

    monkeypatch.setattr(mds_cache, "CACHE", mds_cache.SnapshotCache())
    monkeypatch.setattr(visitor_session, "CLEANUP", visitor_session.CleanupState())


@pytest.fixture
def sessions():
    """``server.app.mds.uploads``: a visitor's uploaded metadata."""

    return importlib.import_module("server.app.mds.uploads")


@pytest.fixture
def entries():
    """``server.app.mds.entries``: uploaded statements, read."""

    return importlib.import_module("server.app.mds.entries")


@pytest.fixture
def blob():
    """``server.app.mds.cache``: the snapshot loaders and their cache."""

    return importlib.import_module("server.app.mds.cache")


@pytest.fixture
def uploads():
    """``server.app.storage.github_mirror``: the uploads' GitHub mirror."""

    return importlib.import_module("server.app.storage.github_mirror")


@pytest.fixture
def effective():
    """``server.app.mds.effective``: the snapshot merged with a visitor's uploads."""

    return importlib.import_module("server.app.mds.effective")


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
    """``server.app.mds.verifier``: fido2's MDS verifier."""

    return importlib.import_module("server.app.mds.verifier")


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
