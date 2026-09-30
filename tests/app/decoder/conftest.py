"""Shared fixtures for the decoder runtime tests.

Each fixture hands back the ``server.app.decoder.decode`` submodule that
*defines* a group of helpers. Patch there rather than on the package itself: the
submodules call each other through these module objects, so this is the binding
actually read. The package re-exports the same objects for callers, but a patch
applied to a re-export is not seen by the submodules.

``raising`` is deliberately left at its default everywhere. These names have
moved module more than once; if one moves again the patch must fail loudly
rather than quietly attaching to a dead attribute and leaving the test to pass
while exercising the real code.
"""

from __future__ import annotations

import importlib

import pytest


def _fragment(name: str):
    return importlib.import_module(f"server.app.decoder.decode.{name}")


@pytest.fixture
def ctap():
    """The submodule that classifies, parses, interprets and repairs CTAP payloads."""

    return _fragment("ctap")


@pytest.fixture
def cbor_parser():
    """The submodule that parses CBOR: strict, lenient and sequence forms."""

    return _fragment("cbor_parser")


@pytest.fixture
def keys():
    """The submodule that coerces and varies CBOR mapping keys."""

    return _fragment("keys")


@pytest.fixture
def certificates():
    """The submodule that summarises and converts X.509 certificates."""

    return _fragment("certificates")


@pytest.fixture
def attestation_module():
    """``server.app.webauthn.attestation`` -- the decoder fragments import from it."""

    return importlib.import_module("server.app.webauthn.attestation")
