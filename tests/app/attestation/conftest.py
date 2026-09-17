"""Shared fixtures for the attestation runtime tests.

Each fixture hands back the ``attestation_parts`` fragment that *defines* a
group of helpers. Patch there rather than on ``server.app.attestation``: the
fragments call each other through these modules, so this is the binding that is
actually read. ``server.app.attestation`` re-exports the same objects for
callers, but a patch applied to the re-export is not seen by the fragments.

``raising`` is deliberately left at its default everywhere. These names moved
module once already; if one moves again the patch must fail loudly rather than
quietly attaching to a dead attribute and leaving the test to pass while
exercising the real code.
"""

from __future__ import annotations

import pytest


def _fragment(name: str):
    return pytest.importorskip(f"server.app.attestation_parts.{name}")


@pytest.fixture
def encoding_leaf():
    """The fragment that defines the hex/base64url encoding helpers."""

    return _fragment("encoding_leaf")


@pytest.fixture
def signature_leaf():
    """The fragment that defines the X.509 name and algorithm helpers."""

    return _fragment("certificate_signature_leaf")


@pytest.fixture
def extensions_leaf():
    """The fragment that defines the certificate extension serializers."""

    return _fragment("certificate_extensions_leaf")


@pytest.fixture
def public_key_leaf():
    """The fragment that defines the public-key serializers."""

    return _fragment("certificate_public_key_leaf")


@pytest.fixture
def summary_runtime():
    """The fragment that defines the certificate summary builder."""

    return _fragment("certificate_summary_runtime")


@pytest.fixture
def serialize_runtime():
    """The fragment that defines ``serialize_attestation_certificate``."""

    return _fragment("certificate_serialize_runtime")


@pytest.fixture
def details_runtime():
    """The fragment that defines ``extract_attestation_details``."""

    return _fragment("certificate_details_runtime")


@pytest.fixture
def trust_runtime():
    """The fragment that defines the trust-path and certificate helpers."""

    return _fragment("trust_runtime")


@pytest.fixture
def trust_ca_runtime():
    """The fragment that defines the trusted-CA allowlist helpers."""

    return _fragment("trust_ca_runtime")


@pytest.fixture
def classical_runtime():
    """The fragment that defines the classical attestation root evaluation."""

    return _fragment("classical_runtime")


@pytest.fixture
def pqc_runtime():
    """The fragment that defines the PQC attestation root evaluation."""

    return _fragment("pqc_runtime")


@pytest.fixture
def pqc_constraints_runtime():
    """The fragment that defines the PQC certificate constraint checks."""

    return _fragment("pqc_constraints_runtime")


@pytest.fixture
def checks_input_runtime():
    """The fragment that defines the client/authenticator data checks."""

    return _fragment("checks_input_runtime")


@pytest.fixture
def checks_attestation_runtime():
    """The fragment that defines the attestation signature and root checks."""

    return _fragment("checks_attestation_runtime")


@pytest.fixture
def checks_metadata_runtime():
    """The fragment that defines the metadata result finalisation."""

    return _fragment("checks_metadata_runtime")


@pytest.fixture
def metadata_module():
    """``server.app.metadata`` -- the fragments call into it through the module."""

    return pytest.importorskip("server.app.metadata")
