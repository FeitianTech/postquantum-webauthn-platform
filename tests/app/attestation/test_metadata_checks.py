"""``webauthn.attestation.metadata_checks``: what an MDS entry says of the credential's authenticator.

``finalize_metadata_results`` runs in every registration (``test_checks.py``, the
metadata-finalisation golden); these are what an entry's own fields decide.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from server.app.mds import entries as mds_entries
from server.app.mds import statement_fields
from server.app.webauthn.attestation import metadata_checks

from ..metadata import mds_fixture


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


def _fixture_entry(description):
    """An entry of the fixture snapshot's verified payload, as JSON."""

    payload = json.loads((mds_fixture.SNAPSHOT_DIR / "fido-mds3.verified.json").read_text(encoding="utf-8"))
    return next(raw for raw in payload["entries"] if raw.get("metadataStatement", {}).get("description") == description)


def _finalized(metadata_entry, aaguid=b"\x01" * 16):
    results = {"authenticator_data": {"algorithm": -7}, "errors": [], "warnings": []}
    metadata_checks.finalize_metadata_results(
        results,
        metadata_entry=metadata_entry,
        metadata_lookup_source="aaguid" if metadata_entry is not None else None,
        verifier=None,
        credential_aaguid_bytes=aaguid,
        certificate_aaguid_bytes=b"",
        root_check_details=None,
        root_valid=None,
    )
    return results


def test_the_entrys_latest_status_and_certification_are_read_as_the_explorer_reads_them():
    raw = _fixture_entry("Fixture Security Key L1")

    metadata = _finalized(mds_entries.parse_entry(raw))["metadata"]

    assert metadata["latest_status"] == statement_fields.latest_status(raw["statusReports"]) == "FIDO Certified L1"
    assert metadata["certification_level"] == statement_fields.certification_level(raw["statusReports"])
    assert metadata["certification_level"] == "FIDO Certified L1 • Fixture Security Key • (FIDO20020260901001)"


def test_without_an_entry_or_its_status_reports_nothing_is_said_of_its_status():
    without = _finalized(None, aaguid=b"")["metadata"]
    unreported = _finalized(mds_entries.parse_entry(_fixture_entry("Fixture Key Without Status Reports")))["metadata"]

    assert (without["available"], without["latest_status"], without["certification_level"]) == (False, None, None)
    assert (unreported["available"], unreported["latest_status"], unreported["certification_level"]) == (True, None, None)


def _reported(*statuses):
    """An entry whose status reports say ``statuses``, each a day later than the one before."""

    entry = _entry({})
    entry.status_reports = [{"status": status, "effectiveDate": f"2026-01-{day:02d}"} for day, status in enumerate(statuses, 1)]
    return entry


@pytest.mark.parametrize(
    "status",
    ["USER_VERIFICATION_BYPASS", "ATTESTATION_KEY_COMPROMISE", "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE"],
)
def test_a_latest_status_that_says_the_authenticator_is_not_to_be_trusted_is_a_finding(status):
    results = _finalized(_reported("FIDO_CERTIFIED_L1", status))

    assert results["errors"] == [f"metadata_status_unsafe: {status}"]
    assert results["metadata"]["certification_level"] == "FIDO Certified L1"


@pytest.mark.parametrize(
    "statuses",
    [
        ("NOT_FIDO_CERTIFIED",),
        ("SELF_ASSERTION_SUBMITTED",),
        ("FIDO_CERTIFIED_L2", "UPDATE_AVAILABLE"),
        ("FIDO_CERTIFIED_L3PLUS",),
        # A compromise an update since has dealt with is no longer the latest.
        ("USER_VERIFICATION_BYPASS", "UPDATE_AVAILABLE"),
    ],
)
def test_the_other_statuses_and_the_certification_levels_are_shown_not_findings(statuses):
    results = _finalized(_reported(*statuses))

    assert results["errors"] == []
    assert results["metadata"]["latest_status"] == statement_fields.latest_status(
        [{"status": status, "effectiveDate": "2026-01-01"} for status in statuses[-1:]]
    )
