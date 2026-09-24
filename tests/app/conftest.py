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

from collections.abc import Mapping
from typing import Any

import pytest

# Every app a test builds gets this secret, so building one never reads or
# writes instance/session-secret.key.
TEST_SECRET_KEY = "test-session-secret-0123456789abcdef"


@pytest.fixture(scope="session", autouse=True)
def _session_metadata_outside_the_checkout(tmp_path_factory):
    """Point the session-metadata store at this run's own directory, for the whole run.

    A test that needs a directory of its own still patches one in; this is what
    it falls back to when that patch is undone. A session-cleanup worker thread
    can outlive the test that started it, and one listing the default directory
    removes the inactive sessions it finds there -- the checkout's.
    """

    from server.app.storage import session_metadata

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(session_metadata, "SESSION_METADATA_DIR", str(tmp_path_factory.mktemp("session-metadata")))
        yield


@pytest.fixture
def make_app():
    """Build a fresh app with ``create_app()``; keyword arguments override config.

    The environment is read when the app is built, so ``monkeypatch.setenv``
    before calling this configures that app and no other.
    """

    factory = pytest.importorskip("server.app.factory")

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


def _app():
    """Import the application, which is what registers the Flask routes.

    Every fixture below goes through this. The route tests used to get the
    registration as a side effect of their own
    ``pytest.importorskip("server.app.routes.advanced")`` line; now that they
    reach the fragments instead, the registration has to come from somewhere, and
    a fixture is the honest place for it -- otherwise a file that happens to use
    only ``config_module`` passes in a full run and 404s on its own.
    """

    return pytest.importorskip("server.app.app")


def _advanced_fragment(name: str):
    _app()
    return pytest.importorskip(f"server.app.routes.advanced.{name}")


def _simple_fragment(name: str):
    _app()
    return pytest.importorskip(f"server.app.routes.simple.{name}")


def _module(path: str):
    _app()
    return pytest.importorskip(path)


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
def advanced_binary():
    """The submodule that decodes base64url and extracts binary values."""

    return _advanced_fragment("binary")


@pytest.fixture
def advanced_constants():
    """The submodule that holds the COSE name tables and heavy-field key sets."""

    return _advanced_fragment("constants")


@pytest.fixture
def advanced_tracing():
    """The submodule that records the advanced-flow debug traces."""

    return _advanced_fragment("tracing")


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
def simple_binary():
    """The submodule that decodes the simple flow's binary values."""

    return _simple_fragment("binary")


@pytest.fixture
def simple_parsing():
    """The submodule that parses and serialises session credentials."""

    return _simple_fragment("parsing")


@pytest.fixture
def simple_credential_list():
    """The submodule that serves the credential list route and its builders."""

    return _simple_fragment("credential_list")


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
    """``server.app.webauthn.metadata`` -- the metadata session identity."""

    return _module("server.app.webauthn.metadata")


@pytest.fixture
def attestation_module():
    """``server.app.webauthn.attestation`` -- attestation checks and JSON-safety helpers."""

    return _module("server.app.webauthn.attestation")


@pytest.fixture
def credential_artifacts_module():
    """``server.app.credential_artifacts`` -- advanced credential artifacts."""

    return _module("server.app.credential_artifacts")


@pytest.fixture
def device_logs_module():
    """``server.app.device_logs`` -- registration event recording."""

    return _module("server.app.device_logs")


@pytest.fixture
def pqc_module():
    """``server.app.webauthn.pqc`` -- post-quantum algorithm discovery and naming."""

    return _module("server.app.webauthn.pqc")


@pytest.fixture
def challenge_registry_module():
    """``server.app.challenge_registry`` -- ceremony state stamping and single-use consumption."""

    return _module("server.app.challenge_registry")
