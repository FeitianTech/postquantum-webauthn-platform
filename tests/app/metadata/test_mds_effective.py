"""``mds.effective``: the packaged snapshot with a visitor's uploads in front.

An upload takes the place of the packaged entry with its AAGUID, the first upload of
an AAGUID wins, and a lookup finds the visitor's entry before the packaged one.
"""
from __future__ import annotations

import pytest

from server.app import visitor_session
from server.app.mds import effective as mds_effective
from server.app.mds import uploads as mds_uploads
from server.app.storage import session_metadata

PACKAGED = "f1d0f1d0-0000-4000-8000-000000000001"
PACKAGED_AAID = "F1D0#0012"


def _upload(description: str, aaguid: str | None = None):
    raw = {"metadataStatement": {"description": description}}
    if aaguid:
        raw["aaguid"] = aaguid
    return mds_uploads.save_session_metadata_item(raw)


def test_uploads_come_first_one_per_aaguid_in_place_of_the_packaged_entry(visitor, mds_fixture_snapshot):
    _upload("Uploaded", PACKAGED)
    _upload("Uploaded again", PACKAGED)
    _upload("No AAGUID")

    snapshot = mds_effective.load_effective_full_snapshot()

    assert snapshot["meta"]["baseEntryCount"] == 32
    assert snapshot["meta"]["customEntryCount"] == 2
    assert snapshot["meta"]["entryCount"] == 33
    assert snapshot["meta"]["hasCustomEntries"] is True
    assert [entry.get("source") for entry in snapshot["entries"][:3]] == ["session", "session", None]
    assert sum(entry["aaguid"] == PACKAGED for entry in snapshot["entries"]) == 1
    # The uploads come whole; the packaged entries as the list has them, each
    # without its detail, which its detailUrl names.
    uploaded, packaged = snapshot["entries"][0], snapshot["entries"][2]
    assert uploaded["isLightweightEntry"] is False and uploaded["metadataStatement"]["description"] == "No AAGUID"
    assert packaged["isLightweightEntry"] is True and "metadataStatement" not in packaged
    assert packaged["detailUrl"].startswith("/assets/mds/entries/")


def test_without_a_snapshot_the_uploads_are_the_whole_snapshot(visitor):
    _upload("Uploaded", PACKAGED)

    snapshot = mds_effective.load_effective_full_snapshot()

    assert (snapshot["meta"]["entryCount"], snapshot["meta"]["baseEntryCount"]) == (1, 0)


def test_an_upload_is_found_before_the_packaged_entry_with_its_aaguid(visitor, mds_fixture_snapshot):
    _upload("Uploaded", PACKAGED)

    by_aaguid = mds_effective.resolve_effective_metadata_entry(aaguid=PACKAGED.upper())
    by_id = mds_effective.resolve_effective_metadata_entry(entry_id=by_aaguid["entryId"])

    assert by_aaguid["source"] == by_id["source"] == "session"
    assert by_aaguid["sourceInfo"]["storedFilename"].endswith(".json")


def test_an_upload_without_its_info_file_is_shown_without_its_names(visitor, mds_fixture_snapshot):
    stored = _upload("Uploaded", PACKAGED)
    session_metadata.delete_file(visitor_session.current_id(), f"{stored.filename}.meta.json")

    entry = mds_effective.resolve_effective_metadata_entry(aaguid=PACKAGED)

    assert set(entry["sourceInfo"]) == {"storedFilename", "modifiedAt"}


@pytest.mark.parametrize(
    ("lookup", "source"),
    [({"aaid": PACKAGED_AAID}, "packaged"), ({"aaguid": "f1d0f1d0-0000-4000-8000-000000000002"}, "packaged")],
)
def test_a_packaged_entry_is_found_by_its_aaguid_or_aaid_past_the_one_an_upload_replaced(visitor, mds_fixture_snapshot, lookup, source):
    _upload("Uploaded", PACKAGED)

    assert mds_effective.resolve_effective_metadata_entry(**lookup)["source"] == source


@pytest.mark.parametrize("lookup", [{"aaid": "missing"}, {"aaguid": "   "}, {}])
def test_a_lookup_that_names_no_entry_finds_none(visitor, mds_fixture_snapshot, lookup):
    assert mds_effective.resolve_effective_metadata_entry(**lookup) is None


def test_without_a_snapshot_a_packaged_lookup_finds_none(visitor):
    assert mds_effective.resolve_effective_metadata_entry(aaguid=PACKAGED) is None


def test_an_entry_whose_statement_is_no_object_matches_no_aaguid():
    # Readers give a statement object; a direct call gives the matcher another.
    assert mds_effective._entry_matches_lookup({"metadataStatement": 123}, aaguid=PACKAGED) is False
    assert mds_effective._entry_matches_lookup({"metadataStatement": 123}) is False


@pytest.mark.parametrize("snapshot", [{"meta": "not-a-mapping", "entries": [{"aaguid": PACKAGED}, "not-a-mapping"]}, {"entries": "not-a-list"}])
def test_a_snapshot_whose_meta_or_entries_are_not_what_they_should_be_keeps_what_it_can(visitor, snapshot):
    # The cache hands over the snapshot as read; a direct call gives the composition a malformed one.
    composed = mds_effective._compose_effective_snapshot(snapshot, include_detail=False)

    assert composed["meta"]["baseEntryCount"] == len([entry for entry in snapshot["entries"] if isinstance(entry, dict)])
