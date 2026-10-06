"""``mds.cache``: the packaged snapshot's files, read into the caches between requests.

The packaged explorer snapshot is trusted by its content (a meta describing the
verified snapshot), not by file modification times; what cannot be read is rebuilt
from the verified snapshot, or is nothing.
"""

from __future__ import annotations

import json
import os
import types

import pytest

from server.app.mds import cache as mds_cache
from server.app.mds import files as mds_files
from tests.app.metadata.cache_locks import FillingLock

META = {"no": 7, "etag": "7"}


@pytest.fixture
def snapshot_dir(monkeypatch, tmp_path, metadata_state):
    """An empty snapshot directory, the one the setting names."""

    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def packaged_snapshot(monkeypatch, snapshot_dir):
    """A verified snapshot and a packaged explorer an instant older; rebuilding is counted."""

    verified_path = snapshot_dir / "fido-mds3.verified.json"
    explorer_path = snapshot_dir / "fido-mds3.explorer.json"
    verified_path.write_text(json.dumps({"entries": []}), encoding="utf-8")
    explorer_path.write_text(
        json.dumps({"entries": [], "meta": {"no": 7, "source": "packaged-snapshot"}}),
        encoding="utf-8",
    )

    # Simulate a checkout where the explorer file ends up slightly older.
    os.utime(explorer_path, (1_000.0, 1_000.0))
    os.utime(verified_path, (1_000.5, 1_000.5))

    builds = []
    monkeypatch.setattr(
        mds_cache,
        "build_explorer_snapshot",
        lambda payload, cache: builds.append(1) or {"entries": [], "meta": {"source": "rebuilt"}},
    )
    monkeypatch.setattr(mds_cache, "load_metadata_cache_entry", lambda: None)

    return types.SimpleNamespace(paths=(verified_path, explorer_path), builds=builds)


def _write_meta(verified_path, explorer_path, *, verified_no=7, explorer_no=7):
    (verified_path.parent / (verified_path.name + ".meta.json")).write_text(
        json.dumps({"no": verified_no, "etag": "7", "generated_at": "2026-09-10T00:00:00+00:00"}),
        encoding="utf-8",
    )
    (explorer_path.parent / (explorer_path.name + ".meta.json")).write_text(
        json.dumps(
            {
                "no": explorer_no,
                "etag": "7",
                "generatedAt": "2026-09-10T00:00:00+00:00",
                "source": "packaged",
            }
        ),
        encoding="utf-8",
    )


def test_matching_meta_uses_packaged_snapshot_despite_older_mtime(packaged_snapshot):
    _write_meta(*packaged_snapshot.paths)

    snapshot, _ = mds_cache._load_base_explorer_snapshot()

    assert snapshot["meta"]["source"] == "packaged-snapshot"
    assert packaged_snapshot.builds == []


def test_mismatched_meta_rebuilds_from_verified_snapshot(packaged_snapshot):
    _write_meta(*packaged_snapshot.paths, explorer_no=6)

    snapshot, _ = mds_cache._load_base_explorer_snapshot()

    assert snapshot["meta"]["source"] == "rebuilt"
    assert packaged_snapshot.builds == [1]


def test_summary_reads_meta_file_without_loading_snapshot(packaged_snapshot, monkeypatch):
    _write_meta(*packaged_snapshot.paths)
    monkeypatch.setattr(
        mds_cache,
        "_load_base_explorer_snapshot",
        lambda: pytest.fail("summary should not load the full explorer snapshot"),
    )

    summary = mds_cache.load_packaged_explorer_summary()

    assert summary["no"] == 7
    assert summary["source"] == "packaged"


@pytest.mark.parametrize("meta", ["[]", "{not json"])
def test_a_verified_meta_that_is_no_object_gives_no_cached_headers(snapshot_dir, meta):
    (snapshot_dir / mds_files.VERIFIED_META).write_text(meta, encoding="utf-8")

    assert mds_cache.load_metadata_cache_entry() == {}


def test_cached_headers_are_trimmed_and_the_iso_date_read_from_the_header(snapshot_dir):
    (snapshot_dir / mds_files.VERIFIED_META).write_text(
        json.dumps({"last_modified": "Wed, 21 Oct 2015 07:28:00 GMT", "last_modified_iso": "  ", "etag": " etag ", "fetched_at": 5}),
        encoding="utf-8",
    )

    assert mds_cache.load_metadata_cache_entry() == {
        "last_modified": "Wed, 21 Oct 2015 07:28:00 GMT",
        "last_modified_iso": "2015-10-21T07:28:00+00:00",
        "etag": "etag",
        "fetched_at": None,
    }


@pytest.mark.parametrize("verified", [None, "{not json", "[]"])
def test_without_a_readable_verified_snapshot_there_are_no_entries(snapshot_dir, verified):
    if verified is not None:
        (snapshot_dir / mds_files.VERIFIED).write_text(verified, encoding="utf-8")

    assert mds_cache.load_verified_entries() is None


@pytest.mark.parametrize("explorer", ["a directory", "[]"])
def test_a_packaged_explorer_that_cannot_be_read_is_rebuilt_from_the_verified_snapshot(mds_fixture_snapshot, explorer):
    explorer_path = mds_fixture_snapshot / mds_files.EXPLORER
    explorer_path.unlink()
    if explorer == "a directory":
        explorer_path.mkdir()
    else:
        explorer_path.write_text(explorer, encoding="utf-8")

    snapshot, _ = mds_cache._load_base_explorer_snapshot()

    assert len(snapshot["entries"]) == 32
    # The rebuilt snapshot's meta is what the summary shows, now it is cached.
    assert mds_cache.load_packaged_explorer_summary() == snapshot["meta"]


@pytest.mark.parametrize("full", ["a directory", '{"entries": "not a list"}'])
def test_a_packaged_full_snapshot_that_cannot_be_read_is_rebuilt(mds_fixture_snapshot, full):
    full_path = mds_fixture_snapshot / mds_files.EXPLORER_FULL
    full_path.unlink()
    if full == "a directory":
        full_path.mkdir()
    else:
        full_path.write_text(full, encoding="utf-8")

    snapshot, _ = mds_cache._load_base_full_snapshot()

    assert len(snapshot["entries"]) == 32


def test_without_any_snapshot_there_is_no_full_snapshot_and_no_summary(snapshot_dir):
    assert mds_cache._load_base_full_snapshot() == (None, (None, None, None, None))
    assert mds_cache.load_packaged_explorer_summary() == {}


def test_an_explorer_meta_that_is_no_object_does_not_describe_the_snapshot(mds_fixture_snapshot):
    (mds_fixture_snapshot / mds_files.EXPLORER_META).write_text("[]", encoding="utf-8")

    assert mds_cache._load_packaged_explorer_meta() is None


def test_a_packaged_explorer_without_an_object_meta_is_summarised_from_the_verified_snapshot(mds_fixture_snapshot):
    (mds_fixture_snapshot / mds_files.EXPLORER_META).write_text("[]", encoding="utf-8")
    (mds_fixture_snapshot / mds_files.EXPLORER).write_text('{"entries": [], "meta": "none"}', encoding="utf-8")
    verified = json.loads((mds_fixture_snapshot / mds_files.VERIFIED).read_text(encoding="utf-8"))

    summary = mds_cache.load_packaged_explorer_summary()
    built = mds_cache.build_explorer_snapshot(verified, mds_cache.load_metadata_cache_entry())["meta"]

    # Built again, it differs only in when it was built.
    assert summary.pop("generatedAt") and built.pop("generatedAt")
    assert summary == built
    assert summary["entryCount"] == 32



_EXPLORER_MARKER = (mds_files.EXPLORER, mds_files.VERIFIED, mds_files.EXPLORER_META, mds_files.VERIFIED_META)
_FULL_MARKER = (mds_files.EXPLORER_FULL, mds_files.VERIFIED, mds_files.EXPLORER_FULL_META, mds_files.VERIFIED_META)


@pytest.mark.parametrize(
    ("load", "lock", "value", "marker", "names"),
    [
        (mds_cache._load_base_explorer_snapshot, "explorer_lock", "explorer", "explorer_mtime", _EXPLORER_MARKER),
        (mds_cache._load_base_full_snapshot, "full_lock", "full", "full_mtime", _FULL_MARKER),
        (mds_cache.load_explorer_files, "explorer_files_lock", "explorer_files", "explorer_files_mtime", _FULL_MARKER),
    ],
)
def test_what_another_thread_loaded_while_this_one_waited_for_the_lock_is_used(
    mds_fixture_snapshot, monkeypatch, load, lock, value, marker, names
):
    loaded = types.SimpleNamespace(name="loaded by the thread that held the lock")

    def fill():
        setattr(mds_cache.CACHE, value, loaded)
        setattr(mds_cache.CACHE, marker, mds_cache._mtimes(*names))

    monkeypatch.setattr(mds_cache.CACHE, lock, FillingLock(fill))
    answer = load()

    assert (answer[0] if isinstance(answer, tuple) else answer) is loaded


def test_cache_cleaning_and_formatting_helpers():
    assert mds_cache._clean_metadata_cache_value("  etag-value  ") == "etag-value"
    assert mds_cache._clean_metadata_cache_value("   ") is None
