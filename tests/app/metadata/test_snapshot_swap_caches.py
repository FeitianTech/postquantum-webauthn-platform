"""A snapshot replaced file by file under a running instance is never kept half old.

The metadata caches key on the files they read. When the full snapshot's cache
keyed on the verified snapshot alone, replacing that file first let a request
cache the old explorer rows under the new key, and keep serving them.
"""

from __future__ import annotations

import json
import os

from server.app.mds import cache as blob
from server.app.mds import files as mds_files
from tests.app.metadata.snapshot_versions import snapshot_version


def _replace_one_by_one(directory, files, order, loads):
    stamp = os.path.getmtime(directory / mds_files.VERIFIED)
    for step, name in enumerate(order, start=1):
        path = directory / name
        path.write_bytes(files[name])
        os.utime(path, (stamp + step, stamp + step))
        for load in loads:
            load()


def test_the_full_snapshot_follows_every_file_it_was_built_from(mds_fixture_snapshot):
    newer = snapshot_version(8)
    assert blob._load_base_full_snapshot()[0]["meta"]["entryCount"] == 32

    # The verified snapshot first: until the rest lands, the old explorer rows
    # still agree with the old metas and are what a request gets.
    order = (mds_files.VERIFIED,) + tuple(
        name for name in mds_files.SNAPSHOT_FILENAMES if name != mds_files.VERIFIED
    )
    _replace_one_by_one(
        mds_fixture_snapshot,
        newer,
        order,
        (blob._load_base_full_snapshot, blob._load_base_explorer_snapshot, blob.load_explorer_files),
    )

    full, _ = blob._load_base_full_snapshot()
    explorer, _ = blob._load_base_explorer_snapshot()
    assert full["meta"]["no"] == 8 and full["meta"]["entryCount"] == 3
    assert explorer["meta"]["no"] == 8 and len(explorer["entries"]) == 3
    browsers = blob.load_explorer_files()
    assert browsers.version.startswith("8.")
    assert len(json.loads(browsers.list_json)["entries"]) == 3


def test_the_metas_landing_last_move_every_cache(mds_fixture_snapshot):
    newer = snapshot_version(9)
    blob._load_base_full_snapshot()
    blob._load_base_explorer_snapshot()

    payloads = tuple(name for name in mds_files.SNAPSHOT_FILENAMES if not name.endswith(".meta.json"))
    metas = tuple(name for name in mds_files.SNAPSHOT_FILENAMES if name.endswith(".meta.json"))
    _replace_one_by_one(
        mds_fixture_snapshot,
        newer,
        payloads + metas,
        (blob._load_base_full_snapshot, blob._load_base_explorer_snapshot),
    )

    assert blob._load_base_full_snapshot()[0]["meta"]["no"] == 9
    assert blob._load_base_explorer_snapshot()[0]["meta"]["no"] == 9
