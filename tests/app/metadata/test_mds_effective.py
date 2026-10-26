"""``mds.effective``: a visitor's uploads as the explorer lists them, in front of the packaged entries.

An upload takes the place of the packaged entry with its AAGUID, the first upload of
an AAGUID wins, and a lookup finds the visitor's entry before the packaged one.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from fido2.mds3 import MetadataBlobPayloadEntry

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from server.app.mds import effective as mds_effective
from server.app.mds import explorer_files
from server.app.mds import files as mds_files
from server.app.mds import uploads as mds_uploads
from server.app.storage import session_metadata
from tests.app.metadata.upload_entries import _entry_payload

PACKAGED = "f1d0f1d0-0000-4000-8000-000000000001"
PACKAGED_AAID = "F1D0#0012"
PNG = b"\x89PNG\r\n\x1a\n" + b"uploaded icon" * 4
PNG_ICON = f"data:image/png;base64,{base64.b64encode(PNG).decode()}"


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
    # One upload per AAGUID, each a row of the packaged list's shape: the entry page asks for its detail.
    packaged = mds_cache.load_explorer_files().listed["entries"][0]
    assert [set(entry) for entry in custom["entries"]] == [set(packaged) - {"detailUrl"}] * 2
    assert sum(entry["aaguid"] == PACKAGED for entry in custom["entries"]) == 1
    assert "No AAGUID" in {entry["name"] for entry in custom["entries"]}
    assert all(entry["isLightweightEntry"] is True for entry in custom["entries"])


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


def test_an_uploads_row_is_its_detail_in_the_lists_shape_as_a_packaged_entrys_is(visitor, mds_fixture_snapshot):
    _upload("Uploaded", PACKAGED)

    (listed,) = mds_effective.load_custom_entries()["entries"]
    resolved = mds_effective.resolve_effective_metadata_entry(entry_id=listed["entryId"])

    assert explorer_files.list_row(resolved) == listed
    assert resolved["metadataStatement"]["description"] == "Uploaded"
    assert resolved["rawEntry"] is None
    assert mds_effective.resolve_effective_metadata_entry(aaguid=PACKAGED) == resolved


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


def _aged(stored, seconds):
    """Give the upload ``stored`` the modification time ``seconds``: uploads are listed newest first."""

    path = Path(os.environ["FIDO_SERVER_SESSION_METADATA_DIR"]) / visitor_session.current_id() / stored.filename
    os.utime(path, (seconds, seconds))


def test_an_uploads_icon_is_listed_as_the_url_that_serves_it_and_resolved_so(visitor):
    stored = _upload_statement("With an icon", icon=PNG_ICON)

    (row,) = mds_effective.load_custom_entries()["entries"]

    assert row["icon"] == mds_effective.icon_url(stored.filename) == f"/api/mds/metadata/custom/{stored.filename}/icon"
    assert mds_effective.resolve_effective_metadata_entry(entry_id=row["entryId"])["icon"] == row["icon"]


def test_uploads_with_one_image_name_the_oldest_ones_icon(visitor):
    oldest = _upload_statement("Oldest", icon=PNG_ICON)
    newer = _upload_statement("Newer", icon=PNG_ICON)
    other = _upload_statement("Another image", icon=f"data:image/png;base64,{base64.b64encode(PNG + b'2').decode()}")
    for stored, seconds in ((oldest, 1_000), (newer, 2_000), (other, 3_000)):
        _aged(stored, seconds)

    icons = {row["name"]: row["icon"] for row in mds_effective.load_custom_entries()["entries"]}

    assert icons == {
        "Another image": mds_effective.icon_url(other.filename),
        "Newer": mds_effective.icon_url(oldest.filename),
        "Oldest": mds_effective.icon_url(oldest.filename),
    }


def test_an_icon_no_file_is_made_of_is_listed_as_it_is(visitor):
    _upload_statement("An image no file is made of", icon="data:image/bmp;base64,Qk0=")
    _upload_statement("No icon")

    icons = {row["name"]: row["icon"] for row in mds_effective.load_custom_entries()["entries"]}

    assert icons == {"An image no file is made of": "data:image/bmp;base64,Qk0=", "No icon": ""}


def test_an_icons_url_names_its_upload_whole():
    assert mds_effective.icon_url("a#b.json") == "/api/mds/metadata/custom/a%23b.json/icon"


def test_an_uploads_icon_is_its_image(visitor):
    stored = _upload_statement("With an icon", icon=PNG_ICON)

    assert mds_effective.upload_icon(stored.filename) == explorer_files.Icon(PNG, "image/png")


def test_no_icon_is_had_of_an_upload_without_an_image_or_of_no_upload(visitor):
    without = _upload("No icon")
    unserved = _upload_statement("An image no file is made of", icon="data:image/bmp;base64,Qk0=")

    assert mds_effective.upload_icon(without.filename) is None
    assert mds_effective.upload_icon(unserved.filename) is None
    assert mds_effective.upload_icon("missing.json") is None


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
