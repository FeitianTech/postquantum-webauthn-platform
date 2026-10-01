"""Shared fixtures for the app tests: an app built from the environment, its client,
fresh MDS state, the fixture snapshot and a small export of the UI."""

from __future__ import annotations

import shutil
from collections.abc import Mapping
from typing import Any

import pytest

from server.app import factory, visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import provisioning as mds_provisioning
from tests.app.metadata import mds_fixture
from tests.app.web_export_files import write, write_export

# Every app a test builds gets this secret, so building one never reads or
# writes instance/session-secret.key.
TEST_SECRET_KEY = "test-session-secret-0123456789abcdef"


@pytest.fixture(scope="session", autouse=True)
def _the_snapshot_provisioning_attempted_once():
    """Make this process's one provisioning attempt before any test runs.

    The MDS routes and registration complete wait for it, and its first attempt
    logs a WARNING when no snapshot is available, as in every test run (the
    snapshot directory is empty, the upstream refresh off). Made here, that one
    warning does not land inside whichever test happens to come first: a test that
    counts the warnings a registration logs would otherwise pass or fail by run order.
    A test that provisions for itself patches the state and the lock it needs.
    """


    mds_provisioning.ensure_snapshot_available()


@pytest.fixture
def make_app():
    """Build a fresh app with ``create_app()``; keyword arguments override config.

    The environment is read when the app is built, so ``monkeypatch.setenv``
    before calling this configures that app and no other.
    """

    def _make(config: Mapping[str, Any] | None = None):
        return factory.create_app(
            {"TESTING": True, "SECRET_KEY": TEST_SECRET_KEY, **(config or {})}
        )

    return _make


@pytest.fixture
def app(make_app):
    """A fresh app, built with the test configuration."""

    return make_app()


@pytest.fixture
def client(app):
    """A test client for ``app``."""

    return app.test_client()


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
def mds_fixture_snapshot(monkeypatch, tmp_path, metadata_state):
    """The fixture snapshot (tests/fixtures/mds/snapshot), copied into this test's
    directory and made the snapshot directory. Copied, never served in place, so
    nothing a test does lands in the checkout; with fresh modification times,
    since the metadata caches key on them."""


    target = tmp_path / "mds-snapshot"
    shutil.copytree(mds_fixture.SNAPSHOT_DIR, target, copy_function=shutil.copy)
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(target))
    return target


@pytest.fixture
def export_root(tmp_path):
    """A small static export of the UI in ``tmp_path/out`` (``web_export_files``),
    with a ``secret.txt`` beside it that nothing may serve."""


    write(tmp_path / "secret.txt", b"outside the export")
    return write_export(tmp_path / "out")
