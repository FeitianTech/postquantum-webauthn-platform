"""``mds.listed_uploads``: each of a visitor's uploads worked out once, kept in its info file
when it is saved and in memory for its version, so that a listing of the namespace reads and
parses only what was written since, and reads no upload whose info keeps it."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from fido2.mds3 import MetadataBlobPayloadEntry
from hypothesis import HealthCheck, given, reject, settings
from hypothesis import strategies as st

from server.app import visitor_session
from server.app.mds import entries as mds_entries
from server.app.mds import explorer_files, listed_uploads, verifier
from server.app.mds import uploads as mds_uploads
from server.app.storage import session_metadata
from tests.app.metadata.upload_entries import _entry_payload
from tests.app.storage import fake_gcs

PNG = b"\x89PNG\r\n\x1a\n" + b"listed icon" * 4
PNG_ICON = f"data:image/png;base64,{base64.b64encode(PNG).decode()}"


def _save(description: str, **fields):
    """Save an upload as releases before its info kept its listing did."""

    return mds_uploads.save_session_metadata_item({"metadataStatement": {"description": description}, **fields})


def _save_listed(raw: dict, **options):
    """Save an upload as the upload route does: its listing kept in its info."""

    return mds_uploads.save_session_metadata_item(raw, listed=listed_uploads.stored_form, **options)


def _write(namespace: str, name: str, description: str) -> Path:
    session_metadata.write_file(namespace, name, json.dumps({"metadataStatement": {"description": description}}).encode())
    return Path(os.environ["FIDO_SERVER_SESSION_METADATA_DIR"]) / namespace / name


@pytest.fixture
def reads(monkeypatch):
    """The uploads the listings read from the store, by stored name."""

    names: list[str] = []
    read = mds_uploads.read_stored_upload

    def _read(namespace, upload, info=None):
        names.append(upload.filename)
        return read(namespace, upload, info)

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


def _listing_bytes(uploads: list[listed_uploads.ListedUpload]) -> int:
    return len(json.dumps([[upload.row, upload.item] for upload in uploads]))


def test_uploads_a_client_made_huge_are_listed_small_and_kept(visitor, reads):
    huge = 15 * 2**20
    _save("Icon", metadataStatement={"description": "Icon", "icon": "data:image/bmp;base64," + "Qk0A" * (huge // 4)})
    _save("Name", metadataStatement={"description": "N" * huge})
    _save("List", metadataStatement={"description": "List", "keyProtection": ["key_" + "k" * 60] * (huge // 70)})

    first = listed_uploads.list_uploads()
    reads.clear()

    assert _listing_bytes(first) < 64 * 2**10
    by_name = {upload.row["name"][:4]: upload.row for upload in first}
    assert by_name["Icon"]["icon"] == ""
    assert by_name["NNNN"]["name"] == "N" * 253 + "..."
    assert len(by_name["List"]["keyProtectionList"]) == 16
    assert listed_uploads.list_uploads() == first
    assert reads == []


def _description_for_row_weight(weight: int) -> str:
    """A description whose upload's row weighs ``weight`` bytes as JSON."""

    base = _entry_payload(aaguid="f1d0f1d0-0000-4000-8000-000000000000", description="")
    item = mds_uploads.SessionMetadataItem(
        filename="0" * 32 + ".json", payload=base, legal_header=None, entry=None,
        uploaded_at="2026-01-01T00:00:00.000000+00:00", original_filename=None, mtime=1.0,
    )
    unnamed = explorer_files.list_row(listed_uploads.upload_entry(item, index=0, include_detail=False))
    return "d" * (weight - len(json.dumps(unnamed)))


def test_a_namespace_at_its_count_quota_of_rows_at_their_bound_is_listed_and_kept_whole(visitor, reads, monkeypatch):
    # An eighth of the count quota (2,000 uploads) in an eighth of the budget: what each
    # upload at the bound costs is what the quota's would, in an eighth of the time.
    monkeypatch.setattr(listed_uploads, "KEPT", listed_uploads.KeptUploads(listed_uploads.BUDGET_BYTES // 8))
    description = _description_for_row_weight(listed_uploads.ROW_BOUND_BYTES - 100)
    namespace = visitor_session.ensure_id()
    for number in range(250):
        payload = _entry_payload(aaguid=f"f1d0f1d0-0000-4000-8000-{number:012d}", description=description)
        session_metadata.write_file(namespace, f"{number:032d}.json", json.dumps(payload).encode())
    first = listed_uploads.list_uploads()
    reads.clear()

    assert len(first) == 250
    # Left as they are, each just under the bound: none is cut down.
    assert all(upload.row["name"] == description for upload in first)
    assert max(len(json.dumps(upload.row)) for upload in first) in range(listed_uploads.ROW_BOUND_BYTES - 1_000, listed_uploads.ROW_BOUND_BYTES + 1)
    assert _listing_bytes(first) <= 16 * 2**20 // 8
    assert listed_uploads.list_uploads() == first
    assert reads == []


def _kept(name: str, size: int = 1_000) -> listed_uploads.ListedUpload:
    return listed_uploads.ListedUpload(
        filename=name, mtime=None, item={}, row={"name": "x" * size}, icon_file=None, aaguid_key="", aaid=None,
        verifier_keys=listed_uploads.VerifierKeys(hides=None, aaguid=None, revoked=False, key_identifiers=()),
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


def test_the_heaviest_row_a_statement_can_make_is_cut_to_its_bound():
    # Every text and list at its largest, in characters JSON writes as ``\\uXXXX`` pairs.
    text = "\U0001F511" * 20_000
    texts = [f"{number}{text}" for number in range(100)]
    payload = {
        "aaid": text,
        "timeOfLastStatusChange": text,
        "statusReports": [{"status": "FIDO_CERTIFIED_L1", "certificationDescriptor": text, "certificateNumber": text}],
        "metadataStatement": {
            "description": text, "protocolFamily": text, "icon": "data:image/bmp;base64," + "Qk0A" * 100_000,
            "attachmentHint": texts, "keyProtection": texts, "authenticationAlgorithms": texts, "transports": texts,
            "userVerificationDetails": [[{"userVerificationMethod": method}] for method in texts],
        },
    }
    entry = MetadataBlobPayloadEntry.from_dict(_entry_payload(aaguid="f1d0f1d0-0000-4000-8000-000000000000", description=""))
    item = mds_uploads.SessionMetadataItem(
        filename="0" * 32 + ".json", payload=payload, legal_header=text, entry=entry,
        uploaded_at="2026-01-01T00:00:00+00:00", original_filename=text, mtime=1.0,
    )

    upload = listed_uploads._listed_upload(item)

    assert len(json.dumps(upload.row)) <= listed_uploads.ROW_BOUND_BYTES
    assert len(json.dumps(upload.item)) <= listed_uploads.ROW_BOUND_BYTES
    # Still the page's row: every field there, the entry named, its lists' first items shortened.
    assert upload.row.keys() == explorer_files.list_row(listed_uploads.upload_entry(item, index=0, include_detail=False)).keys()
    assert upload.row["name"].startswith("\U0001F511") and upload.row["name"].endswith("...")
    assert len(upload.row["keyProtectionList"]) == 16
    assert all(len(json.dumps(method)) <= 2 + 32 for method in upload.row["keyProtectionList"])


def test_a_row_still_too_heavy_once_its_texts_and_lists_are_cut_keeps_what_identifies_it():
    row = {
        "entryId": "aaid:F1D0#0001", "name": "Named", "id": "F1D0#0001", "aaguid": "", "source": "session", "index": 3,
        "sourceInfo": {"storedFilename": "kept.json", "originalFilename": "dropped.json"},
        "transportsList": ["usb"] * 20, **{f"field{number}": "t" * 200 for number in range(100)},
    }

    bounded = listed_uploads._bounded(row)

    assert bounded == {
        "entryId": "aaid:F1D0#0001", "name": "Named", "id": "F1D0#0001", "aaguid": "", "source": "session", "index": 3,
        "sourceInfo": {"storedFilename": "kept.json", "originalFilename": ""},
        "transportsList": [], **{f"field{number}": "" for number in range(100)},
    }


FIXTURE_ENTRIES = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures/mds/snapshot/fido-mds3.verified.json").read_text()
)["entries"]


def _key_identifiers(seed: int, count: int) -> list[str]:
    return [hashlib.sha1(f"{seed}/{number}".encode()).hexdigest() for number in range(count)]


@st.composite
def _uploaded_statements(draw):
    """An upload as visitors make them: a fixture entry, or its statement alone, with or
    without an AAGUID, an icon, key identifiers, a revocation, and fields long enough to be
    cut down."""

    entry = copy.deepcopy(draw(st.sampled_from(FIXTURE_ENTRIES)))
    statement = entry["metadataStatement"]
    if "aaguid" in entry:
        aaguid = draw(st.one_of(st.none(), st.uuids().map(str)))
        for holder in (entry, statement):
            holder.pop("aaguid", None)
            if aaguid is not None:
                holder["aaguid"] = aaguid
    count = draw(st.sampled_from([0, 1, 64, 65]))
    identifiers = _key_identifiers(draw(st.integers(0, 2**16)), count)
    for holder in (entry, statement):
        holder.pop("attestationCertificateKeyIdentifiers", None)
        if identifiers:
            holder["attestationCertificateKeyIdentifiers"] = identifiers
    icon = draw(st.sampled_from([None, "fixture", PNG_ICON, "data:image/bmp;base64,Qk0=", "data:image/bmp;base64," + "Qk0A" * 4_000]))
    if icon is None:
        statement.pop("icon", None)
    elif icon != "fixture":
        statement["icon"] = icon
    text = draw(st.text(max_size=12))
    statement["description"] = text * draw(st.sampled_from([1, 1_000])) or "Unnamed"
    if draw(st.booleans()):
        statement["keyProtection"] = [f"key_{number}" for number in range(draw(st.integers(0, 40)))]
    if draw(st.booleans()):
        entry["statusReports"] = [*entry.get("statusReports", []), {"status": "REVOKED", "effectiveDate": "2025-06-01"}]
    if draw(st.booleans()):
        entry["legalHeader"] = draw(st.text(max_size=8))
    return statement if draw(st.booleans()) else entry


@settings(max_examples=150, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(raw=_uploaded_statements(), original_filename=st.one_of(st.none(), st.text(max_size=12)))
def test_what_an_info_file_keeps_of_an_upload_is_what_is_worked_out_from_it(visitor, raw, original_filename):
    try:
        saved = _save_listed(raw, original_filename=original_filename)
    except mds_entries.MetadataRefused:
        reject()
    namespace, stored = mds_uploads.list_stored_uploads()
    (upload,) = [upload for upload in stored if upload.filename == saved.filename]

    from_info = listed_uploads._kept_from(upload, mds_uploads.stored_listing(upload, mds_uploads.read_stored_info(namespace, upload)))
    worked_out = listed_uploads._listed_upload(mds_uploads.read_stored_upload(namespace, upload))

    assert from_info == worked_out
    # Every member in the same order, the bytes as fido2 reads them.
    assert json.dumps([from_info.item, from_info.row]) == json.dumps([worked_out.item, worked_out.row])


def test_the_stored_form_of_an_upload_is_pinned_with_its_format():
    entry = FIXTURE_ENTRIES[0]
    components = mds_entries.build_metadata_entry_components(json.loads(mds_uploads.stored_json(entry)))
    item = mds_uploads.SessionMetadataItem(
        "0" * 32 + ".json", components[2], components[1], components[0],
        uploaded_at="2026-01-01T00:00:00+00:00", original_filename="pinned.json", mtime=None,
    )
    stored = listed_uploads.stored_form(item)
    shape = json.dumps({key: value for key, value in stored.items() if key != "format"})

    assert stored["format"] == listed_uploads.STORED_FORMAT
    assert (listed_uploads.ROW_FORMAT, hashlib.sha256(shape.encode()).hexdigest()) == (
        1, "4bfd8736932338966ddd0cadb0a76d516d5c3f2a787e6bacc761d06d3b204cba",
    ), "What an upload's info file keeps of it changed: bump listed_uploads.ROW_FORMAT, then this pin."


@pytest.fixture(params=["local", "gcs"])
def store_calls(request, monkeypatch, visitor):
    """What the store is asked, on the backend the test runs on: the files read, by name, the
    entries parsed and the files written or deleted."""

    if request.param == "gcs":
        fake_gcs.install(monkeypatch, session_metadata)
    calls = {"read": [], "parsed": 0, "written": 0}
    read, write, delete, parse = (
        session_metadata.read_file, session_metadata.write_file, session_metadata.delete_file,
        mds_entries.build_metadata_entry_components,
    )

    def _read(namespace, name):
        calls["read"].append(name)
        return read(namespace, name)

    def _write(*args, **kwargs):
        calls["written"] += 1
        return write(*args, **kwargs)

    def _delete(*args, **kwargs):
        calls["written"] += 1
        return delete(*args, **kwargs)

    def _parse(raw):
        calls["parsed"] += 1
        return parse(raw)

    monkeypatch.setattr(session_metadata, "read_file", _read)
    monkeypatch.setattr(session_metadata, "write_file", _write)
    monkeypatch.setattr(session_metadata, "delete_file", _delete)
    monkeypatch.setattr(mds_entries, "build_metadata_entry_components", _parse)
    return calls


def _forget(monkeypatch, calls):
    """Drop what this process keeps of the uploads, and what the store was asked so far."""

    monkeypatch.setattr(listed_uploads, "KEPT", listed_uploads.KeptUploads())
    calls.update(read=[], parsed=0, written=0)


def _aaguid_entry(number: int) -> dict:
    return _entry_payload(aaguid=f"f1d0f1d0-0000-4000-8000-{number:012d}", description=f"Upload {number}")


def test_a_listing_with_nothing_kept_reads_each_uploads_info_alone_and_writes_nothing(store_calls, monkeypatch):
    saved = [_save_listed(_aaguid_entry(number)) for number in range(12)]
    by_name = {item.filename: item for item in saved}
    _forget(monkeypatch, store_calls)

    listed = listed_uploads.list_uploads()

    assert sorted(store_calls["read"]) == sorted(f"{name}.meta.json" for name in by_name)
    assert (store_calls["parsed"], store_calls["written"]) == (0, 0)
    item = mds_uploads.load_session_metadata_item
    assert listed == [listed_uploads._listed_upload(item(upload.filename)) for upload in listed]
    assert {upload.filename for upload in listed} == set(by_name)


def test_a_registrations_first_lookup_reads_the_infos_and_the_one_upload_it_finds(store_calls, monkeypatch):
    saved = [_save_listed(_aaguid_entry(number)) for number in range(12)]
    _forget(monkeypatch, store_calls)

    found = verifier.get_mds_verifier().find_entry_by_aaguid(bytes.fromhex("f1d0f1d0000040008000000000000005"))

    assert found.metadata_statement.description == "Upload 5"
    assert sorted(store_calls["read"]) == sorted([f"{item.filename}.meta.json" for item in saved] + [saved[5].filename])
    assert (store_calls["parsed"], store_calls["written"]) == (1, 0)


def _info_path(filename: str) -> Path:
    return Path(os.environ["FIDO_SERVER_SESSION_METADATA_DIR"]) / visitor_session.current_id() / f"{filename}.meta.json"


def _rewrite_listed(filename: str, change) -> None:
    path = _info_path(filename)
    info = json.loads(path.read_text())
    change(info)
    path.write_text(json.dumps(info))


@pytest.mark.parametrize(
    "change",
    [
        lambda info: info.pop("listed"),
        lambda info: info["listed"].update(format="0.0 fido2 0.0"),
        lambda info: info["listed"].pop("row"),
        lambda info: info["listed"].update(row="a row"),
        lambda info: info["listed"].update(aaguid="not hex"),
        lambda info: info["listed"].update(key_identifiers=[7]),
        lambda info: info.update(listed=[]),
    ],
    ids=["saved-before", "another-format", "partial", "wrong-type", "bad-hex", "bad-identifier", "not-an-object"],
)
def test_an_upload_whose_info_keeps_no_listing_it_can_read_is_read_and_listed_as_before(visitor, monkeypatch, reads, change):
    saved = _save_listed(_aaguid_entry(1))
    expected = listed_uploads.list_uploads()
    _rewrite_listed(saved.filename, change)
    monkeypatch.setattr(listed_uploads, "KEPT", listed_uploads.KeptUploads())
    reads.clear()

    assert listed_uploads.list_uploads() == expected
    assert reads == [saved.filename]


def test_an_upload_whose_info_does_not_read_is_read_and_listed_without_its_names(visitor, monkeypatch, reads):
    saved = _save_listed(_aaguid_entry(1), original_filename="named.json")
    _info_path(saved.filename).write_text('{"listed": {"format"')
    reads.clear()

    (upload,) = listed_uploads.list_uploads()

    assert upload.item["source"] == {"storedFilename": saved.filename}
    assert reads == [saved.filename]


def test_an_info_file_of_another_upload_is_never_listed_for_this_one(visitor, reads):
    first, second = _save_listed(_aaguid_entry(1)), _save_listed(_aaguid_entry(2))
    _info_path(second.filename).write_bytes(_info_path(first.filename).read_bytes())
    reads.clear()

    rows = {upload.filename: upload.row["name"] for upload in listed_uploads.list_uploads()}

    assert rows == {first.filename: "Upload 1", second.filename: "Upload 2"}
    assert reads == [second.filename]


def test_an_entry_written_again_after_its_info_is_read_again_even_at_its_size(visitor, reads):
    saved = _save_listed(_aaguid_entry(1))
    path = _info_path(saved.filename).with_name(saved.filename)
    path.write_text(path.read_text().replace("Upload 1", "Upload 9"))
    info_written = _info_path(saved.filename).stat().st_mtime
    os.utime(path, (info_written + 1, info_written + 1))
    reads.clear()

    (upload,) = listed_uploads.list_uploads()

    assert upload.row["name"] == "Upload 9"
    assert reads == [saved.filename]


def test_an_entry_of_another_size_than_its_info_keeps_is_read_again(visitor, reads):
    saved = _save_listed(_aaguid_entry(1))
    path = _info_path(saved.filename).with_name(saved.filename)
    info_written = _info_path(saved.filename).stat().st_mtime
    path.write_text(path.read_text().replace("Upload 1", "Upload 10"))
    os.utime(path, (info_written - 1, info_written - 1))
    reads.clear()

    (upload,) = listed_uploads.list_uploads()

    assert upload.row["name"] == "Upload 10"
    assert reads == [saved.filename]
