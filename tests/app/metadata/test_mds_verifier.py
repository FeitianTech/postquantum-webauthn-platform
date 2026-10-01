"""``mds.verifier``: the MDS metadata attestations are checked against, a visitor's uploads first."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest
from flask import g

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import uploads as mds_uploads
from server.app.mds import verifier as mds_verifier

PACKAGED = "f1d0f1d0-0000-4000-8000-000000000001"
OTHER = "0badc0de-0000-4000-8000-000000000001"


@pytest.fixture
def visitor(monkeypatch, tmp_path, metadata_state, make_app):
    """A request whose visitor can upload metadata into a store of this test's."""

    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))
    monkeypatch.setattr(visitor_session, "schedule_cleanup", lambda: None)
    with make_app().test_request_context("/"):
        yield


def _upload(aaguid: str, description: str, legal_header: str | None = None):
    raw = {"aaguid": aaguid, "metadataStatement": {"description": description, "aaguid": aaguid}}
    if legal_header:
        raw["legalHeader"] = legal_header
    return mds_uploads.save_session_metadata_item(raw)


def _descriptions(metadata) -> list[str]:
    return [entry.metadata_statement.description for entry in metadata.entries]


def test_an_upload_takes_the_place_of_the_packaged_entry_with_its_aaguid(visitor, mds_fixture_snapshot):
    base, _ = mds_cache._load_base_metadata()

    merged = mds_verifier._merge_metadata(base, [_upload(PACKAGED, "Uploaded")])

    assert len(merged.entries) == len(base.entries)
    assert _descriptions(merged)[0] == "Uploaded"
    assert "Fixture Security Key L1" not in _descriptions(merged)
    assert merged.legal_header == base.legal_header


def test_packaged_metadata_without_a_legal_header_takes_an_uploads(visitor, mds_fixture_snapshot):
    base, _ = mds_cache._load_base_metadata()
    items = [_upload(OTHER, "No header"), _upload(PACKAGED, "Headed", legal_header="Upload Legal")]

    merged = mds_verifier._merge_metadata(replace(base, legal_header=""), items)

    assert merged.legal_header == "Upload Legal"


def test_uploads_without_a_snapshot_are_metadata_of_their_own_one_entry_per_aaguid(visitor):
    items = [_upload(OTHER, "First"), _upload(OTHER, "Second"), _upload(PACKAGED, "Headed", legal_header="Upload Legal")]

    merged = mds_verifier._merge_metadata(None, items)
    unheaded = mds_verifier._merge_metadata(None, items[:1])

    assert _descriptions(merged) == ["First", "Headed"]
    assert (merged.legal_header, merged.no, merged.next_update) == ("Upload Legal", 0, datetime.now(timezone.utc).date())
    assert unheaded.legal_header == ""


def test_the_verifier_holds_the_visitors_uploads_and_never_trusts_them(visitor):
    _upload(OTHER, "Uploaded")

    verifier = mds_verifier.get_mds_verifier()

    (entry,) = g._mds_session_entries
    assert verifier is not None
    assert mds_verifier.metadata_entry_trust_anchor_status(entry) is False
    assert mds_verifier.metadata_entry_trust_anchor_status(object()) is None
