"""``webauthn.attestation.metadata_checks``: what an MDS entry says of the credential's authenticator.

``finalize_metadata_results`` runs in every registration (``test_checks.py``, the
metadata-finalisation golden); these are what an entry's own fields decide.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from server.app.webauthn.attestation import metadata_checks


def _entry(get_info):
    return SimpleNamespace(metadata_statement=SimpleNamespace(authenticator_get_info=get_info))


@pytest.mark.parametrize(
    ("algorithms", "supported"),
    [
        # As the MDS writes them.
        ([{"alg": -7, "type": "public-key"}, {"alg": -8, "type": "public-key"}], True),
        ([{"alg": -257, "type": "public-key"}], False),
        # Bare numbers are read too, and the two side by side.
        ([-7], True),
        ([-257, {"alg": -8, "type": "public-key"}], False),
        ([-257, {"alg": -7, "type": "public-key"}], True),
    ],
)
def test_the_credentials_algorithm_is_looked_for_among_the_ones_getinfo_lists(algorithms, supported):
    facts = metadata_checks._metadata_entry_facts(_entry({"algorithms": algorithms}), -7)

    assert facts["algorithm_supported"] is supported


@pytest.mark.parametrize(
    "get_info",
    [
        {},
        {"algorithms": "ES256"},
        {"algorithms": [{"type": "public-key"}, {"alg": "ES256"}, "ES256"]},
        None,
    ],
)
def test_without_an_algorithm_listed_nothing_is_said_of_the_credentials(get_info):
    assert metadata_checks._metadata_entry_facts(_entry(get_info), -7)["algorithm_supported"] is None


def test_a_credential_without_a_numeric_algorithm_is_not_compared():
    facts = metadata_checks._metadata_entry_facts(_entry({"algorithms": [{"alg": -7, "type": "public-key"}]}), None)

    assert facts["algorithm_supported"] is None


def test_an_entry_that_omits_the_credentials_algorithm_is_an_error_of_its_results():
    results = {"authenticator_data": {"algorithm": -35}, "errors": [], "warnings": []}

    metadata_checks.finalize_metadata_results(
        results,
        metadata_entry=_entry({"algorithms": [{"alg": -7, "type": "public-key"}]}),
        metadata_lookup_source="aaguid",
        verifier=None,
        credential_aaguid_bytes=b"\x01" * 16,
        certificate_aaguid_bytes=b"",
        root_check_details=None,
        root_valid=None,
    )

    assert results["errors"] == ["algorithm_not_in_metadata"]
    assert results["metadata"]["algorithm_supported"] is False
