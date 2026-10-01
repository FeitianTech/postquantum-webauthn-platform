"""The MDS fixture the tests and the browser tests serve is what its generator
builds, and holds what the explorer must show well.

``tests/app/metadata/mds_fixture.py`` builds it with the updater's own code; this
fails when the committed files differ. ``MDS_FIXTURE_WRITE=1`` rewrites them
(review the diff, as for the characterization goldens).
"""
from __future__ import annotations

import io
import json
import os

import pytest

from server.app.mds import cache as mds_cache
from server.app.mds import files as mds_files
from tests.app.metadata import mds_fixture


def test_the_committed_fixture_is_what_the_generator_builds():
    built = mds_fixture.build_fixture_files()
    if os.environ.get(mds_fixture.WRITE_ENV):
        mds_fixture.write_fixture()

    committed = {
        path.relative_to(mds_fixture.FIXTURE_DIR).as_posix(): path.read_bytes()
        for path in sorted(mds_fixture.FIXTURE_DIR.rglob("*"))
        if path.is_file()
    }
    assert sorted(committed) == sorted(built), (
        f"The files under tests/fixtures/mds differ; run with {mds_fixture.WRITE_ENV}=1 to rewrite them."
    )
    changed = sorted(name for name, data in built.items() if committed[name] != data)
    assert changed == [], f"{changed} changed; run with {mds_fixture.WRITE_ENV}=1 to rewrite them."


def _full_snapshot():
    return json.loads((mds_fixture.SNAPSHOT_DIR / mds_files.EXPLORER_FULL).read_text(encoding="utf-8"))


def test_the_fixture_is_a_whole_snapshot():
    assert sorted(path.name for path in mds_fixture.SNAPSHOT_DIR.iterdir()) == sorted(mds_files.SNAPSHOT_FILENAMES)


def test_the_fixture_holds_what_the_explorer_must_show_well():
    entries = _full_snapshot()["entries"]
    assert {entry["protocol"] for entry in entries} == {"FIDO2", "U2F", "Uaf"}
    assert {entry["entryId"].split(":")[0] for entry in entries} == {"aaguid", "aaid", "akid"}
    assert any("#" in entry["entryId"] for entry in entries)
    assert {entry["certificationStatus"] for entry in entries} >= {
        "FIDO_CERTIFIED",
        "FIDO_CERTIFIED_L1",
        "FIDO_CERTIFIED_L2",
        "NOT_FIDO_CERTIFIED",
        "REVOKED",
    }
    assert max(len(entry["commonName"]) for entry in entries) >= 954
    assert max(len(entry["userVerification"]) for entry in entries) >= 194
    assert max(len(entry["name"]) for entry in entries) == 135
    assert any(not entry["icon"] for entry in entries)
    assert all(entry["icon"].startswith("data:image/png;base64,") for entry in entries if entry["icon"])
    assert any(entry["certification"] == "" for entry in entries)
    assert len(entries) >= 30


def test_the_upload_is_one_entry_the_snapshot_does_not_hold():
    upload = json.loads(mds_fixture.CUSTOM_METADATA_PATH.read_text(encoding="utf-8"))
    (entry,) = upload["entries"]
    assert entry["aaguid"] not in {item["aaguid"] for item in _full_snapshot()["entries"]}


def test_flask_serves_the_fixture(mds_fixture_snapshot, client):
    entries = _full_snapshot()["entries"]

    answer = client.get("/api/mds/metadata/explorer/full")
    assert answer.status_code == 200
    assert [entry["entryId"] for entry in answer.get_json()["entries"]] == [entry["entryId"] for entry in entries]

    # A file response holds the file open until it is closed.
    with client.get("/assets/mds/fido-mds3.explorer.full.json") as static:
        assert static.status_code == 200
        assert static.data == (mds_fixture_snapshot / mds_files.EXPLORER_FULL).read_bytes()

    resolved = client.get("/api/mds/metadata/resolve", query_string={"aaid": "F1D0#0012"})
    assert resolved.status_code == 200
    assert resolved.get_json()["entry"]["name"] == "Fixture UAF Authenticator"


def test_an_uploaded_statement_joins_the_fixture(mds_fixture_snapshot, client):
    upload = mds_fixture.CUSTOM_METADATA_PATH.read_bytes()
    answer = client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(upload), "custom-metadata.json")},
        content_type="multipart/form-data",
    )
    assert answer.status_code == 200
    snapshot = answer.get_json()["snapshot"]
    assert snapshot["meta"]["customEntryCount"] == 1
    assert snapshot["entries"][0]["name"] == "Fixture Uploaded Authenticator"
    assert snapshot["entries"][0]["source"] == "session"

    listed = client.get("/api/mds/metadata/custom").get_json()["items"]
    assert [item["source"]["originalFilename"] for item in listed] == ["custom-metadata.json"]

    stored = listed[0]["source"]["storedFilename"]
    removed = client.delete(f"/api/mds/metadata/custom/{stored}")
    assert removed.status_code == 200
    assert removed.get_json()["snapshot"]["meta"]["customEntryCount"] == 0


@pytest.mark.parametrize("name", mds_files.SNAPSHOT_FILENAMES)
def test_serving_the_fixture_never_writes_to_it(mds_fixture_snapshot, client, name):
    before = (mds_fixture.SNAPSHOT_DIR / name).read_bytes()
    client.get("/api/mds/metadata/explorer/full")
    assert (mds_fixture.SNAPSHOT_DIR / name).read_bytes() == before
    assert (mds_fixture_snapshot / name).read_bytes() == before


def test_resolve_serves_a_packaged_entry_as_the_blob_has_it(mds_fixture_snapshot, client):
    # fido2's StatusReport models neither sunsetDate nor certificationProfiles,
    # nor a field no MDS3 version defines yet: none may be lost on the way.
    blob_entry = next(
        entry
        for entry in json.loads((mds_fixture_snapshot / mds_files.VERIFIED).read_text())["entries"]
        if entry.get("aaguid") == "f1d0f1d0-0000-4000-8000-000000000001"
    )

    answer = client.get("/api/mds/metadata/resolve", query_string={"aaguid": blob_entry["aaguid"]})
    assert answer.status_code == 200
    entry = answer.get_json()["entry"]
    assert entry["statusReports"] == blob_entry["statusReports"]
    assert entry["statusReports"][-1]["sunsetDate"] == "2029-09-01"
    assert entry["statusReports"][-1]["fixtureFutureField"] == "A field no MDS3 version defines"
    assert entry["rawEntry"] == blob_entry
    assert entry["timeOfLastStatusChange"] == blob_entry["timeOfLastStatusChange"]


def test_raw_entries_follow_only_the_file_the_metadata_was_read_from(mds_fixture_snapshot, monkeypatch):
    verified = mds_fixture_snapshot / mds_files.VERIFIED
    mtime = os.path.getmtime(verified)

    assert mds_cache._load_base_raw_entries(None) is None
    assert mds_cache._load_base_raw_entries(mtime - 1) is None
    entries = mds_cache._load_base_raw_entries(mtime)
    assert len(entries) == 32
    assert mds_cache._load_base_raw_entries(mtime) is entries

    # A payload without an entry list gives none, and a missing file nothing.
    os.utime(verified, (mtime + 5, mtime + 5))
    monkeypatch.setattr(mds_cache, "_load_verified_metadata_payload", lambda: {"entries": {}})
    assert mds_cache._load_base_raw_entries(mtime + 5) is None
    verified.unlink()
    assert mds_cache._load_base_raw_entries(mtime + 5) is None
