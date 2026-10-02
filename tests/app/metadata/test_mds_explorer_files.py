"""What browsers load of the MDS snapshot, derived from the explorer's full
snapshot: the list the table shows, the icons as files, each entry's detail."""
from __future__ import annotations

import base64
import gzip
import json
from urllib.parse import unquote

import pytest

from server.app.mds import cache as mds_cache
from server.app.mds import explorer_files
from server.app.mds import files as mds_files

PNG = b"\x89PNG\r\n\x1a\n" + b"fixture icon" * 4


@pytest.fixture
def full_snapshot(mds_fixture_snapshot):
    return json.loads((mds_fixture_snapshot / mds_files.EXPLORER_FULL).read_text())


@pytest.fixture
def files(full_snapshot):
    return explorer_files.build_explorer_files(full_snapshot)


def _list(files):
    return json.loads(files.list_json)


def test_the_list_holds_every_entry_without_its_detail_or_where_it_came_from(full_snapshot, files):
    listed = _list(files)

    assert listed["meta"] == full_snapshot["meta"]
    assert [row["entryId"] for row in listed["entries"]] == [entry["entryId"] for entry in full_snapshot["entries"]]
    for row in listed["entries"]:
        assert row["isLightweightEntry"] is True
        assert not explorer_files.LIST_LEAVES_OUT & row.keys()
        assert row["name"] and row["entryId"]
    assert gzip.decompress(files.list_gzip) == files.list_json
    assert files.listed == listed


def test_each_icon_is_a_file_of_its_image_named_by_its_digest(full_snapshot, files):
    rows = {row["entryId"]: row for row in _list(files)["entries"]}

    for entry in full_snapshot["entries"]:
        if not entry.get("icon"):
            assert not rows[entry["entryId"]].get("icon")
            continue
        url = rows[entry["entryId"]]["icon"]
        assert url.startswith("/assets/mds/icons/") and url.endswith(".png")
        icon = files.icons[url.rsplit("/", 1)[1]]
        assert icon.mimetype == "image/png"
        assert icon.data == base64.b64decode(entry["icon"].split(",", 1)[1])
    # The fixture's 31 icons are three images.
    assert len(files.icons) == 3


def test_each_entry_has_its_detail_whole_at_a_url_of_this_version(full_snapshot, files):
    rows = {row["entryId"]: row for row in _list(files)["entries"]}

    for entry in full_snapshot["entries"]:
        row = rows[entry["entryId"]]
        path, version = row["detailUrl"].split("?v=")
        assert version == files.version
        assert unquote(path.removeprefix("/assets/mds/entries/")) == entry["entryId"]
        assert json.loads(files.details[entry["entryId"]]) == {**entry, "icon": row.get("icon")}
    # An AAID's # is part of the path, not a fragment.
    assert rows["aaid:F1D0#0012"]["detailUrl"].startswith("/assets/mds/entries/aaid%3AF1D0%230012?v=")


def test_the_version_names_the_snapshot_and_what_this_code_derives(full_snapshot, files):
    snapshot = explorer_files.snapshot_version(full_snapshot["meta"])

    assert files.version == f"{snapshot}.{explorer_files.DERIVED_FORMAT}"
    assert snapshot.startswith("7.")
    newer = explorer_files.snapshot_version({**full_snapshot["meta"], "etag": '"fixture-8"'})
    assert newer != snapshot


def test_a_snapshot_without_its_meta_has_no_files():
    assert explorer_files.snapshot_version(None) is None
    assert explorer_files.build_explorer_files({"entries": []}) is None


@pytest.mark.parametrize(
    "icon",
    [
        None,
        "",
        "https://example.com/icon.png",
        "data:image/bmp;base64," + base64.b64encode(PNG).decode(),
        "data:image/png," + PNG.hex(),
        "data:image/png;base64,***",
        "data:image/png;base64",
    ],
    ids=["none", "empty", "a-url", "another-type", "not-base64", "unreadable", "no-data"],
)
def test_an_icon_that_is_no_base64_image_of_a_known_type_stays_as_it_is(icon):
    assert explorer_files.icon_file(icon) is None


def test_an_icon_is_read_as_browsers_read_a_data_url():
    name, icon = explorer_files.icon_file("DATA:Image/SVG+XML;BASE64," + base64.b64encode(b"<svg/>").decode().rstrip("=") + "\n")

    assert name.endswith(".svg")
    assert icon == explorer_files.Icon(b"<svg/>", "image/svg+xml")


def test_rows_that_are_not_entries_are_passed_over(full_snapshot):
    files = explorer_files.build_explorer_files({**full_snapshot, "entries": ["not an entry", {"name": "No id"}]})

    assert [row["name"] for row in _list(files)["entries"]] == ["No id"]
    assert "detailUrl" not in _list(files)["entries"][0]
    assert files.details == {}


def test_the_cache_derives_them_once_for_each_snapshot(mds_fixture_snapshot):
    first = mds_cache.load_explorer_files()

    assert mds_cache.load_explorer_files() is first
    assert first.version.startswith("7.")


def test_without_a_snapshot_there_are_no_files(metadata_state, monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))

    assert mds_cache.load_explorer_files() is None
