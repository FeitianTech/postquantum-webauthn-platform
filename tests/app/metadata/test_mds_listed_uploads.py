"""``mds.listed_uploads``: each of a visitor's uploads worked out once for its version, so
that a listing of the namespace reads and parses only what was written since."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from fido2.mds3 import MetadataBlobPayloadEntry

from server.app import visitor_session
from server.app.mds import explorer_files, listed_uploads
from server.app.mds import uploads as mds_uploads
from server.app.storage import session_metadata
from tests.app.metadata.upload_entries import _entry_payload

PNG = b"\x89PNG\r\n\x1a\n" + b"listed icon" * 4
PNG_ICON = f"data:image/png;base64,{base64.b64encode(PNG).decode()}"


def _save(description: str, **fields):
    return mds_uploads.save_session_metadata_item({"metadataStatement": {"description": description}, **fields})


def _write(namespace: str, name: str, description: str) -> Path:
    session_metadata.write_file(namespace, name, json.dumps({"metadataStatement": {"description": description}}).encode())
    return Path(os.environ["FIDO_SERVER_SESSION_METADATA_DIR"]) / namespace / name


@pytest.fixture
def reads(monkeypatch):
    """The uploads the listings read from the store, by stored name."""

    names: list[str] = []
    read = mds_uploads.read_stored_upload

    def _read(namespace, upload):
        names.append(upload.filename)
        return read(namespace, upload)

    monkeypatch.setattr(mds_uploads, "read_stored_upload", _read)
    return names


def test_listing_again_reads_no_upload_and_lists_the_same(visitor, reads):
    saved = [_save("First"), _save("Second")]

    first = listed_uploads.list_uploads()
    assert sorted(reads) == sorted(item.filename for item in saved)
    reads.clear()

    assert listed_uploads.list_uploads() == first
    assert reads == []


def test_an_upload_saved_since_is_the_one_read(visitor, reads):
    _save("First")
    listed_uploads.list_uploads()
    reads.clear()

    later = _save("Later")

    assert {upload.row["name"] for upload in listed_uploads.list_uploads()} == {"First", "Later"}
    assert reads == [later.filename]


def test_an_upload_whose_info_is_written_after_it_is_read_again_with_its_names(visitor, reads):
    namespace = visitor_session.ensure_id()
    _write(namespace, "late.json", "Late")

    (before,) = listed_uploads.list_uploads()
    session_metadata.write_file(namespace, "late.json.meta.json", json.dumps({"original_filename": "late-upload.json"}).encode())
    (after,) = listed_uploads.list_uploads()

    assert before.item["source"] == {"storedFilename": "late.json"}
    assert after.item["source"] == {"storedFilename": "late.json", "originalFilename": "late-upload.json"}
    assert reads == ["late.json", "late.json"]


def test_an_upload_written_again_is_read_again(visitor, reads):
    stored = _save("Before")
    listed_uploads.list_uploads()

    (Path(os.environ["FIDO_SERVER_SESSION_METADATA_DIR"]) / visitor_session.current_id() / stored.filename).write_text(
        json.dumps({"metadataStatement": {"description": "After, and longer"}})
    )

    assert [upload.row["name"] for upload in listed_uploads.list_uploads()] == ["After, and longer"]
    assert reads == [stored.filename, stored.filename]


def test_an_upload_that_does_not_read_is_left_out_and_read_again_once_written_again(visitor, reads):
    namespace = visitor_session.ensure_id()
    session_metadata.write_file(namespace, "broken.json", b"[]")

    assert listed_uploads.list_uploads() == []
    assert listed_uploads.list_uploads() == []
    _write(namespace, "broken.json", "Mended")

    assert [upload.row["name"] for upload in listed_uploads.list_uploads()] == ["Mended"]
    assert reads == ["broken.json", "broken.json"]


def test_each_namespace_keeps_its_own_uploads(visitor, reads):
    # One name, one size and one time in each: only the namespace tells them apart.
    for namespace, description in (("namespace-a", "A's upload"), ("namespace-b", "B's upload")):
        path = _write(namespace, "same.json", description)
        os.utime(path, (1_000, 1_000))

    for namespace, description in (("namespace-a", "A's upload"), ("namespace-b", "B's upload")) * 2:
        assert [upload.row["name"] for upload in listed_uploads.list_uploads(namespace)] == [description]
    assert reads == ["same.json", "same.json"]


def test_what_is_kept_of_an_upload_is_what_its_statement_gives(visitor):
    stored = _save("With an icon", aaguid="f1d0f1d0-0000-4000-8000-0000000000aa", aaid="F1D0#00AA", metadataStatement={
        "description": "With an icon", "icon": PNG_ICON,
    })

    (upload,) = listed_uploads.list_uploads()

    item = mds_uploads.load_session_metadata_item(stored.filename)
    row = explorer_files.list_row(listed_uploads.upload_entry(item, index=0, include_detail=False))
    assert upload.item == mds_uploads.serialize_session_metadata_item(item)
    # Its image is no part of what is kept: the file named for it is.
    assert (upload.row, upload.icon_file) == ({**row, "icon": ""}, explorer_files.icon_file(PNG_ICON)[0])
    assert (upload.aaguid_key, upload.aaid) == ("f1d0f1d00000400080000000000000aa", "F1D0#00AA")


def test_an_icon_no_file_is_made_of_is_kept_in_its_row(visitor):
    _save("Unserved", metadataStatement={"description": "Unserved", "icon": "data:image/bmp;base64,Qk0="})

    (upload,) = listed_uploads.list_uploads()

    assert (upload.row["icon"], upload.icon_file) == ("data:image/bmp;base64,Qk0=", None)


def _kept(name: str, size: int = 1_000) -> listed_uploads.ListedUpload:
    return listed_uploads.ListedUpload(
        filename=name, mtime=None, item={}, row={"name": "x" * size}, icon_file=None, aaguid_key="", aaid=None
    )


def test_past_its_budget_the_least_recently_listed_upload_goes_first():
    weight = listed_uploads._weight(_kept("one"))
    kept = listed_uploads.KeptUploads(budget=8 * weight + weight // 2)
    for number in range(8):
        kept.put(("namespace", f"{number}.json"), ("v",), _kept(f"{number}.json"))

    assert kept.get(("namespace", "0.json"), ("v",)) == (True, _kept("0.json"))
    kept.put(("namespace", "8.json"), ("v",), _kept("8.json"))

    assert kept.get(("namespace", "1.json"), ("v",)) == (False, None)
    assert all(kept.get(("namespace", f"{number}.json"), ("v",))[0] for number in (0, 2, 3, 4, 5, 6, 7, 8))


def test_an_upload_kept_again_at_another_version_takes_its_own_place_alone():
    weight = listed_uploads._weight(_kept("one"))
    kept = listed_uploads.KeptUploads(budget=8 * weight + weight // 2)
    for number in range(7):
        kept.put(("namespace", f"{number}.json"), ("v",), _kept(f"{number}.json"))

    for version in range(20):
        kept.put(("namespace", "again.json"), (version,), _kept("again.json"))

    assert kept.get(("namespace", "again.json"), (18,)) == (False, None)
    assert kept.get(("namespace", "again.json"), (19,)) == (True, _kept("again.json"))
    assert all(kept.get(("namespace", f"{number}.json"), ("v",))[0] for number in range(7))


def test_an_upload_heavier_than_an_eighth_of_the_budget_is_worked_out_each_time():
    weight = listed_uploads._weight(_kept("heavy"))
    kept = listed_uploads.KeptUploads(budget=8 * weight - 1)

    kept.put(("namespace", "heavy.json"), ("v",), _kept("heavy"))
    kept.put(("namespace", "broken.json"), ("v",), None)

    assert kept.get(("namespace", "heavy.json"), ("v",)) == (False, None)
    # One that did not read is kept as such: it is not read again until it changes.
    assert kept.get(("namespace", "broken.json"), ("v",)) == (True, None)


def test_an_uploads_source_names_its_file_and_times():
    payload = _entry_payload(aaguid="AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", description="Session metadata")
    item = mds_uploads.SessionMetadataItem(
        filename="session.json", payload=payload, legal_header="Session Legal", entry=MetadataBlobPayloadEntry.from_dict(payload),
        uploaded_at="2026-04-03T00:00:00+00:00", original_filename="upload.json", mtime=1.0,
    )

    assert listed_uploads._source_info(item) == {
        "storedFilename": "session.json",
        "originalFilename": "upload.json",
        "uploadedAt": "2026-04-03T00:00:00+00:00",
        "modifiedAt": "1970-01-01T00:00:01+00:00",
    }


def test_an_upload_without_names_or_times_names_its_file_alone():
    item = mds_uploads.SessionMetadataItem(
        filename="session.json", payload={}, legal_header=None, entry=None, uploaded_at=None, original_filename=None, mtime=None
    )

    assert listed_uploads._source_info(item) == {"storedFilename": "session.json"}
