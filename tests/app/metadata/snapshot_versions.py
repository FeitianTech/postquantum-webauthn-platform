"""Other versions of the fixture snapshot, for tests that replace one with another.

``snapshot_version(no, entries)`` is the fixture's seven files (tests/fixtures/mds)
renumbered as snapshot ``no`` with its first ``entries`` entries, its BLOB signed
by the fixture's root (``mds_fixture.blob_root``), built by the updater's own
``snapshot_files`` (``server/app/mds/snapshot.py``): a complete, consistent set
whose metas agree, which an instance can derive from its BLOB and meta.
"""

from __future__ import annotations

import json

from server.app.mds import files as mds_files
from server.app.mds import snapshot as mds_snapshot
from tests.app.metadata import mds_fixture


def snapshot_version(no: int, entries: int = 3) -> dict[str, bytes]:
    snapshot = mds_fixture.SNAPSHOT_DIR
    verified = json.loads((snapshot / mds_files.VERIFIED).read_text(encoding="utf-8"))
    verified["no"] = no
    verified["entries"] = verified["entries"][:entries]
    cache_state = json.loads((snapshot / mds_files.VERIFIED_META).read_text(encoding="utf-8"))
    cache_state.update(
        {"no": no, "entryCount": entries, "etag": f'"fixture-{no}"', "generated_at": f"2026-09-{20 + no % 10:02d}T08:00:00+00:00"}
    )
    blob, _root = mds_fixture._signed_blob(verified)
    return mds_snapshot.snapshot_files(blob, verified, cache_state)
