"""Shared fixtures for the decoder runtime tests.

Each fixture hands back the ``decode`` submodule that *defines* a group of
helpers. Patch there rather than on ``server.app.decoder.decode``: the fragments
call each other through these modules, so this is the binding that is actually
read. ``server.app.decoder.decode`` re-exports the same objects for callers, but
a patch applied to the re-export is not seen by the fragments.

``raising`` is deliberately left at its default everywhere. These names moved
module once already; if one moves again the patch must fail loudly rather than
quietly attaching to a dead attribute and leaving the test to pass while
exercising the real code.
"""

from __future__ import annotations

import pytest


def _fragment(name: str):
    return pytest.importorskip(f"server.app.decoder.decode.{name}")


@pytest.fixture
def pipeline_runtime():
    """The fragment that defines the top-level decode pipeline helpers."""

    return _fragment("pipeline_runtime")


@pytest.fixture
def cbor_runtime():
    """The fragment that defines CBOR sequence decoding and CTAP repair."""

    return _fragment("cbor_runtime")


@pytest.fixture
def ctap_parse_runtime():
    """The fragment that defines the CTAP field parsers and converters."""

    return _fragment("ctap_runtime_parse")


@pytest.fixture
def ctap_interpret_runtime():
    """The fragment that defines the CTAP interpretation and expanded JSON."""

    return _fragment("ctap_runtime_interpret")


@pytest.fixture
def details_runtime():
    """The fragment that defines the client and authenticator data details."""

    return _fragment("details_runtime")


@pytest.fixture
def result_runtime():
    """The fragment that defines the decoder payload and result conversion."""

    return _fragment("result_runtime")


@pytest.fixture
def summary_runtime():
    """The fragment that defines the summary rendering helpers."""

    return _fragment("summary_runtime")


@pytest.fixture
def cbor_parser():
    """The fragment that defines the strict CBOR parsing primitives."""

    return _fragment("cbor_parser")


@pytest.fixture
def cbor_lenient():
    """The fragment that defines the lenient CBOR decoding primitives."""

    return _fragment("cbor_lenient")


@pytest.fixture
def binary():
    """The fragment that defines the binary and COSE key extractors."""

    return _fragment("binary")


@pytest.fixture
def keys():
    """The fragment that defines the mapping-key and JSON-safety helpers."""

    return _fragment("keys")


@pytest.fixture
def ctap_classify():
    """The fragment that defines the CTAP map classification and labels."""

    return _fragment("ctap_classify")


@pytest.fixture
def ctap_convert_leaf():
    """The fragment that defines the CTAP field conversion leaves."""

    return _fragment("ctap_convert_leaf")


@pytest.fixture
def ctap_repair_leaf():
    """The fragment that defines the CTAP trailing-field repair helpers."""

    return _fragment("ctap_repair_leaf")


@pytest.fixture
def conversion_leaf():
    """The fragment that defines the credential payload conversion leaves."""

    return _fragment("conversion_leaf")


@pytest.fixture
def certificates():
    """The fragment that defines the certificate summary line builders. The fragment that defines the certificate extension line builders."""

    return _fragment("certificates")


@pytest.fixture
def summary_leaf():
    """The fragment that defines the summary field formatting leaves."""

    return _fragment("summary_leaf")


@pytest.fixture
def attestation_module():
    """``server.app.attestation`` -- the decoder fragments import from it."""

    return pytest.importorskip("server.app.attestation")
