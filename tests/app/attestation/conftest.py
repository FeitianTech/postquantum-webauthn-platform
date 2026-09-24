"""Shared fixtures for the attestation runtime tests.

Each fixture hands back the ``attestation`` submodule that *defines* a
group of helpers. Patch there rather than on ``server.app.webauthn.attestation``: the
fragments call each other through these modules, so this is the binding that is
actually read. ``server.app.webauthn.attestation`` re-exports the same objects for
callers, but a patch applied to the re-export is not seen by the fragments.

``raising`` is deliberately left at its default everywhere. These names moved
module once already; if one moves again the patch must fail loudly rather than
quietly attaching to a dead attribute and leaving the test to pass while
exercising the real code.
"""

from __future__ import annotations

import pytest


def _fragment(name: str):
    return pytest.importorskip(f"server.app.webauthn.attestation.{name}")


@pytest.fixture
def formatting():
    """The fragment that defines the hex/base64url encoding helpers."""

    return _fragment("formatting")


@pytest.fixture
def certificates():
    """The submodule that serializes X.509 certificates and extracts attestation details."""

    return _fragment("certificates")


@pytest.fixture
def certificate_extensions():
    """The submodule that shows an X.509 extension's value."""

    return _fragment("certificate_extensions")


@pytest.fixture
def trust():
    """The fragment that defines the trust-path and certificate helpers. The fragment that defines the trusted-CA allowlist helpers."""

    return _fragment("trust")


@pytest.fixture
def classical():
    """The fragment that defines the classical attestation root evaluation."""

    return _fragment("classical")


@pytest.fixture
def pqc():
    """The fragment that defines the PQC attestation root evaluation. The fragment that defines the PQC certificate constraint checks."""

    return _fragment("pqc")


@pytest.fixture
def checks():
    """The submodule that runs the attestation checks: client and authenticator
    data, the attestation signature and root, the policy, and the metadata result."""

    return _fragment("checks")


@pytest.fixture
def metadata_module():
    """``server.app.webauthn.metadata`` -- the fragments call into it through the module."""

    return pytest.importorskip("server.app.webauthn.metadata")
