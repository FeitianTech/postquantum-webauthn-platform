"""Shared fixtures for the advanced and simple route tests.

Each fixture hands back the ``*_parts`` fragment that *defines* a group of
helpers, or the ``server.app`` module a fragment imports. Patch there rather than
on ``server.app.routes.advanced`` / ``server.app.routes.simple``: the fragments
resolve these names through their own imports, so that is the binding actually
read. The two route modules re-export the same objects for callers, but a patch
applied to a re-export is not seen by the fragments.

``raising`` is deliberately left at its default everywhere. These names moved
module once already; if one moves again the patch must fail loudly rather than
quietly attaching to a dead attribute and leaving the test to pass while
exercising the real code.
"""

from __future__ import annotations

import pytest


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


# The advanced submodules.


@pytest.fixture
def advanced_algorithm_helpers():
    """The fragment that defines the COSE algorithm name, lookup and coercion helpers."""

    return _advanced_fragment("algorithms")


@pytest.fixture
def advanced_artifacts():
    """The fragment that defines the credential-artifact route bodies."""

    return _advanced_fragment("artifacts")


@pytest.fixture
def advanced_authenticate_begin():
    """The fragment that defines the advanced ``/authenticate/begin`` body."""

    return _advanced_fragment("authentication")


@pytest.fixture
def advanced_authenticate_complete():
    """The fragment that defines the advanced ``/authenticate/complete`` body."""

    return _advanced_fragment("authentication")


@pytest.fixture
def advanced_binary_helpers():
    """The fragment that defines the base64url and binary extraction helpers."""

    return _advanced_fragment("binary")


@pytest.fixture
def advanced_constants():
    """The fragment that defines the COSE name tables and the heavy-field key sets."""

    return _advanced_fragment("constants")


@pytest.fixture
def advanced_logging_helpers():
    """The fragment that defines the attestation-response logging helpers."""

    return _advanced_fragment("tracing")


@pytest.fixture
def advanced_parsing_helpers():
    """The fragment that defines the client-supplied credential parsing helpers."""

    return _advanced_fragment("parsing")


@pytest.fixture
def advanced_register_begin():
    """The fragment that defines the advanced ``/register/begin`` body."""

    return _advanced_fragment("registration")


@pytest.fixture
def advanced_register_begin_support():
    """The fragment that defines the register-begin algorithm, exclude-list and extension builders."""

    return _advanced_fragment("registration")


@pytest.fixture
def advanced_register_complete():
    """The fragment that defines the advanced ``/register/complete`` body."""

    return _advanced_fragment("registration")


@pytest.fixture
def advanced_register_complete_finalize():
    """The fragment that defines the artifact-store and device-log finalisation step."""

    return _advanced_fragment("registration")


@pytest.fixture
def advanced_register_complete_material():
    """The fragment that defines the registration material builder."""

    return _advanced_fragment("registration")


@pytest.fixture
def advanced_register_complete_setup():
    """The fragment that defines the register-complete input preparation step."""

    return _advanced_fragment("registration")


@pytest.fixture
def advanced_register_complete_state():
    """The fragment that defines the register-complete session-state resolution step."""

    return _advanced_fragment("registration")


@pytest.fixture
def advanced_summary_helpers():
    """The fragment that defines the storage-id and stored-credential summary helpers."""

    return _advanced_fragment("summary")


# The simple submodules.


@pytest.fixture
def simple_authenticate():
    """The fragment that defines both simple authentication ceremony bodies."""

    return _simple_fragment("authentication")


@pytest.fixture
def simple_binary_helpers():
    """The fragment that defines the base64 padding and binary decode helpers."""

    return _simple_fragment("binary")


@pytest.fixture
def simple_credential_parsing():
    """The fragment that defines the session-credential serialise and parse helpers."""

    return _simple_fragment("parsing")


@pytest.fixture
def simple_credentials_builder_dict():
    """The fragment that defines the dict-shaped credential row builder."""

    return _simple_fragment("credential_list")


@pytest.fixture
def simple_credentials_builder_object():
    """The fragment that defines the object-shaped credential row builders."""

    return _simple_fragment("credential_list")


@pytest.fixture
def simple_credentials_route():
    """The fragment that defines the ``/api/credentials`` body."""

    return _simple_fragment("credential_list")


@pytest.fixture
def simple_register_begin():
    """The fragment that defines the simple ``/register/begin`` body."""

    return _simple_fragment("registration")


@pytest.fixture
def simple_register_complete():
    """The fragment that defines the simple ``/register/complete`` body."""

    return _simple_fragment("registration")


@pytest.fixture
def simple_register_complete_context_authenticator():
    """The fragment that defines the authenticator-data context step."""

    return _simple_fragment("registration")


@pytest.fixture
def simple_register_complete_context_b():
    """The fragment that defines the persistence and response-payload context steps."""

    return _simple_fragment("registration")


@pytest.fixture
def simple_register_complete_context_init():
    """The fragment that defines the registration-context initialisation step."""

    return _simple_fragment("registration")


@pytest.fixture
def simple_register_complete_context_rp_debug():
    """The fragment that defines the RP debug payload context step."""

    return _simple_fragment("registration")


@pytest.fixture
def simple_sign_count():
    """The fragment that defines the signature-counter records and regression helpers."""

    return _simple_fragment("authentication")


# The sibling packages the fragments import from.


@pytest.fixture
def config_module():
    """``server.app.config`` -- the Flask app, RP resolution and origin policy."""

    return _module("server.app.config")


@pytest.fixture
def storage_module():
    """``server.app.storage`` -- credential persistence."""

    return _module("server.app.storage")


@pytest.fixture
def metadata_module():
    """``server.app.metadata`` -- the metadata session identity."""

    return _module("server.app.metadata")


@pytest.fixture
def attestation_module():
    """``server.app.attestation`` -- attestation checks and JSON-safety helpers."""

    return _module("server.app.attestation")


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
    """``server.app.pqc`` -- post-quantum algorithm discovery and naming."""

    return _module("server.app.pqc")


@pytest.fixture
def attachments_module():
    """``server.app.attachments`` -- authenticator attachment normalisation."""

    return _module("server.app.attachments")


@pytest.fixture
def challenge_registry_module():
    """``server.app.challenge_registry`` -- ceremony state stamping and single-use consumption."""

    return _module("server.app.challenge_registry")
