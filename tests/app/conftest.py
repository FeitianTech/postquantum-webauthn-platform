"""Shared fixtures for the advanced and simple route tests.

Each fixture hands back the route submodule that *defines* a group of helpers, or
the ``server.app`` module such a submodule imports. Patch there rather than on the
``server.app.routes.advanced`` / ``server.app.routes.simple`` packages: the
submodules resolve these names through their own imports, so that is the binding
actually read. Each package's ``__init__.py`` re-exports the same objects for
callers, but a patch applied to a re-export is not seen by the submodules.

``raising`` is deliberately left at its default everywhere. These names have moved
module more than once; if one moves again the patch must fail loudly rather than
quietly attaching to a dead attribute and leaving the test to pass while
exercising the real code.
"""

from __future__ import annotations

import importlib
import shutil
from collections.abc import Mapping
from typing import Any

import pytest

from server.app import factory, visitor_session
from server.app.mds import cache as mds_cache

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

    from server.app.mds import provisioning as mds_provisioning

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

    from tests.app.metadata import mds_fixture

    target = tmp_path / "mds-snapshot"
    shutil.copytree(mds_fixture.SNAPSHOT_DIR, target, copy_function=shutil.copy)
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(target))
    return target


@pytest.fixture
def export_root(tmp_path):
    """A small static export of the UI in ``tmp_path/out`` (``web_export_files``),
    with a ``secret.txt`` beside it that nothing may serve."""

    from tests.app.web_export_files import write, write_export

    write(tmp_path / "secret.txt", b"outside the export")
    return write_export(tmp_path / "out")


def _app():
    """Import the application, which is what registers the Flask routes.

    Every fixture below goes through this. The route tests used to get the
    registration as a side effect of their own
    ``pytest.importorskip("server.app.routes.advanced")`` line; now that they
    reach the fragments instead, the registration has to come from somewhere, and
    a fixture is the honest place for it -- otherwise a file that happens to use
    only ``config_module`` passes in a full run and 404s on its own.
    """

    return importlib.import_module("server.app.app")


def _advanced_fragment(name: str):
    _app()
    return importlib.import_module(f"server.app.routes.advanced.{name}")


def _simple_fragment(name: str):
    _app()
    return importlib.import_module(f"server.app.routes.simple.{name}")


def _module(path: str):
    _app()
    return importlib.import_module(path)


# The advanced route submodules.


@pytest.fixture
def advanced_algorithms():
    """The submodule that resolves and names COSE algorithms."""

    return _advanced_fragment("algorithms")


@pytest.fixture
def advanced_artifacts():
    """The submodule that serves the credential-artifact routes."""

    return _advanced_fragment("artifacts")


@pytest.fixture
def advanced_authentication():
    """The submodule that serves the advanced authenticate begin and complete bodies."""

    return _advanced_fragment("authentication")


@pytest.fixture
def advanced_constants():
    """The submodule that holds the COSE name tables and heavy-field key sets."""

    return _advanced_fragment("constants")


@pytest.fixture
def advanced_parsing():
    """The submodule that parses client-supplied credentials."""

    return _advanced_fragment("parsing")


@pytest.fixture
def advanced_registration():
    """The submodule that serves the advanced register begin and complete bodies."""

    return _advanced_fragment("registration")


@pytest.fixture
def advanced_registration_record():
    """The submodule that builds a verified advanced registration's record and stored credential."""

    return _advanced_fragment("registration_record")


@pytest.fixture
def advanced_summary():
    """The submodule that builds the advanced response summaries."""

    return _advanced_fragment("summary")


# The simple route submodules.


@pytest.fixture
def simple_authentication():
    """The submodule that serves the simple authenticate bodies and the sign-count check."""

    return _simple_fragment("authentication")


@pytest.fixture
def simple_parsing():
    """The submodule that parses and serialises session credentials."""

    return _simple_fragment("parsing")


@pytest.fixture
def simple_registration():
    """The submodule that serves the simple register begin and complete bodies."""

    return _simple_fragment("registration")


# The sibling packages the fragments import from.


@pytest.fixture
def config_module():
    """``server.app.config`` -- the Flask app, RP resolution and origin policy."""

    return _module("server.app.config")


@pytest.fixture
def storage_module():
    """``server.app.storage.credentials`` -- credential persistence."""

    return _module("server.app.storage.credentials")


@pytest.fixture
def metadata_module():
    """``server.app.visitor_session`` -- the visitor's session id."""

    return _module("server.app.visitor_session")


@pytest.fixture
def attestation_module():
    """``server.app.webauthn.attestation`` -- attestation checks and JSON-safety helpers."""

    return _module("server.app.webauthn.attestation")


@pytest.fixture
def credential_artifacts_module():
    """``server.app.storage.credential_artifacts`` -- advanced credential artifacts."""

    return _module("server.app.storage.credential_artifacts")


@pytest.fixture
def device_logs_module():
    """``server.app.storage.github_mirror`` -- registration event recording."""

    return _module("server.app.storage.github_mirror")


@pytest.fixture
def pqc_module():
    """``server.app.webauthn.pqc`` -- post-quantum algorithm discovery and naming."""

    return _module("server.app.webauthn.pqc")


@pytest.fixture
def challenge_registry_module():
    """``server.app.challenge_registry`` -- ceremony state stamping and single-use consumption."""

    return _module("server.app.challenge_registry")
