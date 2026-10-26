"""``mds.effective``: a visitor's uploads as the explorer lists them, in front of the packaged entries.

An upload takes the place of the packaged entry with its AAGUID, the first upload of
an AAGUID wins, and a lookup finds the visitor's entry before the packaged one.
"""

from __future__ import annotations

import json

import pytest
from fido2.mds3 import MetadataBlobPayloadEntry

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import effective as mds_effective
from server.app.mds import files as mds_files
from server.app.mds import uploads as mds_uploads
from server.app.storage import session_metadata
from tests.app.metadata.upload_entries import _entry_payload

PACKAGED = "f1d0f1d0-0000-4000-8000-000000000001"
PACKAGED_AAID = "F1D0#0012"


def _upload(description: str, aaguid: str | None = None):
    raw = {"metadataStatement": {"description": description}}
    if aaguid:
        raw["aaguid"] = aaguid
    return mds_uploads.save_session_metadata_item(raw)


def _upload_statement(description: str, **statement):
    return mds_uploads.save_session_metadata_item({"metadataStatement": {"description": description, **statement}})


def test_the_custom_entries_are_the_uploads_alone_with_the_counts_of_the_list_they_make(visitor, mds_fixture_snapshot):
    _upload("Uploaded", PACKAGED)
    _upload("Uploaded again", PACKAGED)
    _upload("No AAGUID")

    custom = mds_effective.load_custom_entries()

    assert custom["meta"] == {"entryCount": 33, "baseEntryCount": 32, "customEntryCount": 2, "hasCustomEntries": True}
    # One upload per AAGUID; each with its detail, as the page shows it without asking.
    assert [entry["source"] for entry in custom["entries"]] == ["session", "session"]
    assert sum(entry["aaguid"] == PACKAGED for entry in custom["entries"]) == 1
    assert "No AAGUID" in {entry["metadataStatement"]["description"] for entry in custom["entries"]}
    assert all(entry["isLightweightEntry"] is False for entry in custom["entries"])


def test_without_uploads_the_custom_entries_are_none_and_the_counts_the_packaged_list(visitor, mds_fixture_snapshot):
    assert mds_effective.load_custom_entries() == {
        "meta": {"entryCount": 32, "baseEntryCount": 32, "customEntryCount": 0, "hasCustomEntries": False},
        "entries": [],
    }


def test_without_a_snapshot_the_custom_entries_count_no_packaged_row(visitor):
    _upload("Uploaded", PACKAGED)

    meta = mds_effective.load_custom_entries()["meta"]

    assert (meta["entryCount"], meta["baseEntryCount"], meta["customEntryCount"]) == (1, 0, 1)


def test_an_upload_with_the_id_of_a_packaged_entry_shown_gets_one_of_its_own(visitor, mds_fixture_snapshot):
    _upload_statement("Uploaded UAF", aaid=PACKAGED_AAID)

    (row,) = mds_effective.load_custom_entries()["entries"]

    assert row["entryId"] == f"aaid:{PACKAGED_AAID}~2"
    resolved = mds_effective.resolve_effective_metadata_entry(entry_id=row["entryId"])
    assert resolved["metadataStatement"]["description"] == "Uploaded UAF"
    assert mds_effective.resolve_effective_metadata_entry(entry_id=f"aaid:{PACKAGED_AAID}")["source"] == "packaged"


def test_uploads_with_one_key_identifier_get_an_id_each(visitor, mds_fixture_snapshot):
    _upload_statement("First", attestationCertificateKeyIdentifiers=["ab" * 20])
    _upload_statement("Second", attestationCertificateKeyIdentifiers=["ab" * 20])

    ids = [row["entryId"] for row in mds_effective.load_custom_entries()["entries"]]

    assert sorted(ids) == [f"akid:{'ab' * 20}", f"akid:{'ab' * 20}~2"]


def test_an_upload_is_found_before_the_packaged_entry_with_its_aaguid(visitor, mds_fixture_snapshot):
    _upload("Uploaded", PACKAGED)

    by_aaguid = mds_effective.resolve_effective_metadata_entry(aaguid=PACKAGED.upper())
    by_id = mds_effective.resolve_effective_metadata_entry(entry_id=by_aaguid["entryId"])

    assert by_aaguid["source"] == by_id["source"] == "session"
    assert by_aaguid["sourceInfo"]["storedFilename"].endswith(".json")


def test_an_upload_is_resolved_as_the_visitors_explorer_list_holds_it(visitor, mds_fixture_snapshot):
    _upload("Uploaded", PACKAGED)

    resolved = mds_effective.resolve_effective_metadata_entry(aaguid=PACKAGED)
    listed = mds_effective.load_custom_entries()["entries"][0]

    assert resolved == listed
    assert resolved["rawEntry"] is None


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
    _upload("No AAGUID")

    assert mds_effective.resolve_effective_metadata_entry(**lookup)["source"] == source


def _with_an_earlier_copy_of_the_packaged_entry(directory):
    # A BLOB with two statements of one AAGUID: the list gives the earlier one an id of its own.
    path = directory / mds_files.EXPLORER_FULL
    full = json.loads(path.read_text(encoding="utf-8"))
    original = next(entry for entry in full["entries"] if entry["entryId"] == f"aaguid:{PACKAGED}")
    full["entries"].insert(0, {**original, "name": "Earlier statement"})
    path.write_text(json.dumps(full), encoding="utf-8")


def test_a_packaged_entry_sharing_its_id_is_resolved_by_its_own(visitor, mds_fixture_snapshot):
    _with_an_earlier_copy_of_the_packaged_entry(mds_fixture_snapshot)

    assert mds_effective.resolve_effective_metadata_entry(entry_id=f"aaguid:{PACKAGED}~2")["name"] == "Earlier statement"
    assert mds_effective.resolve_effective_metadata_entry(entry_id=f"aaguid:{PACKAGED}")["name"] == "Fixture Security Key L1"
    assert mds_effective.resolve_effective_metadata_entry(entry_id=f"aaguid:{PACKAGED}~3") is None


def test_a_packaged_entry_an_upload_hides_is_not_resolved_by_its_id(visitor, mds_fixture_snapshot):
    _with_an_earlier_copy_of_the_packaged_entry(mds_fixture_snapshot)
    _upload("Uploaded", PACKAGED)

    assert mds_effective.resolve_effective_metadata_entry(entry_id=f"aaguid:{PACKAGED}~2") is None


@pytest.mark.parametrize("lookup", [{"aaid": "missing"}, {"aaguid": "   "}, {}])
def test_a_lookup_that_names_no_entry_finds_none(visitor, mds_fixture_snapshot, lookup):
    assert mds_effective.resolve_effective_metadata_entry(**lookup) is None


def test_an_entry_of_the_verified_payload_that_is_no_object_is_passed_over(visitor, mds_fixture_snapshot, monkeypatch):
    entries = mds_cache.load_verified_entries()
    monkeypatch.setattr(mds_cache, "load_verified_entries", lambda: ["not an entry", *entries])

    assert mds_effective.resolve_effective_metadata_entry(aaguid=PACKAGED)["aaguid"] == PACKAGED


def test_without_a_snapshot_a_packaged_lookup_finds_none(visitor):
    assert mds_effective.resolve_effective_metadata_entry(aaguid=PACKAGED) is None


def test_an_entry_whose_statement_is_no_object_matches_no_aaguid():
    # Readers give a statement object; a direct call gives the matcher another.
    assert mds_effective._entry_matches_lookup({"metadataStatement": 123}, aaguid=PACKAGED) is False
    assert mds_effective._entry_matches_lookup({"metadataStatement": 123}) is False


def test_uploaded_entry_source_names_its_file_and_times():
    session_payload = _entry_payload(aaguid='AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA', description='Session metadata')
    session_entry = MetadataBlobPayloadEntry.from_dict(session_payload)
    session_item = mds_uploads.SessionMetadataItem(filename='session.json', payload=session_payload, legal_header='Session Legal', entry=session_entry, uploaded_at='2026-04-03T00:00:00+00:00', original_filename='upload.json', mtime=1.0)
    source_info = mds_effective._session_item_source_info(session_item)
    assert source_info['storedFilename'] == 'session.json'
    assert source_info['originalFilename'] == 'upload.json'
    assert source_info['uploadedAt'] == '2026-04-03T00:00:00+00:00'
    assert 'modifiedAt' in source_info


def test_an_uploaded_entry_without_names_or_times_names_its_file_alone():
    item = mds_uploads.SessionMetadataItem(
        filename="session.json", payload={}, legal_header=None, entry=None, uploaded_at=None, original_filename=None, mtime=None
    )

    assert mds_effective._session_item_source_info(item) == {"storedFilename": "session.json"}
