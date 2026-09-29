"""Other versions of the fixture snapshot, for tests that replace one with another.

``snapshot_version(no, entries)`` is the fixture's seven files (tests/fixtures/mds)
renumbered as snapshot ``no`` with its first ``entries`` entries, built by the
updater's own ``snapshot_files``: a complete, consistent set whose metas agree.
"""

from __future__ import annotations

import json

from server.app import mds_snapshot_dir
from tests.app.metadata import mds_fixture
from tools import update_mds_snapshot as updater


def snapshot_version(no: int, entries: int = 3) -> dict[str, bytes]:
    snapshot = mds_fixture.SNAPSHOT_DIR
    verified = json.loads((snapshot / mds_snapshot_dir.VERIFIED).read_text(encoding="utf-8"))
    verified["no"] = no
    verified["entries"] = verified["entries"][:entries]
    cache_state = json.loads((snapshot / mds_snapshot_dir.VERIFIED_META).read_text(encoding="utf-8"))
    cache_state.update(
        {"no": no, "entryCount": entries, "etag": f'"fixture-{no}"', "generated_at": f"2026-09-{20 + no % 10:02d}T08:00:00+00:00"}
    )
    blob = (snapshot / mds_snapshot_dir.BLOB).read_bytes() + f"\n{no}".encode("ascii")
    return updater.snapshot_files(blob, verified, cache_state)
