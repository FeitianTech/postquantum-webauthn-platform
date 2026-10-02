"""The MDS files web/'s component tests render are the server's own, and stay so.

``web/src/test/mds-files.json`` holds what the server serves of the fixture
snapshot (tests/fixtures/mds): the explorer's list, and each entry's detail by
the path the list names it at. The React component tests answer ``fetch`` with
them rather than with hand-written ones. This asks the app again and fails when
a file has changed. ``MDS_FILES_WRITE=1`` rewrites it (review the diff).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

_FILES = Path(__file__).resolve().parents[3] / "web" / "src" / "test" / "mds-files.json"
_WRITE_ENV = "MDS_FILES_WRITE"


def _served(client) -> dict:
    listed = client.get("/assets/mds/fido-mds3.explorer.list.json", headers={"Accept-Encoding": "identity"})
    assert listed.status_code == 200
    rows = json.loads(listed.data)
    details = {}
    for row in rows["entries"]:
        detail = client.get(row["detailUrl"], headers={"Accept-Encoding": "identity"})
        assert detail.status_code == 200
        details[row["detailUrl"].split("?")[0]] = json.loads(detail.data)
    return {"list": rows, "details": details}


def test_the_web_tests_mds_files_are_what_the_server_serves(mds_fixture_snapshot, client):
    served = _served(client)
    if os.environ.get(_WRITE_ENV) == "1":
        _FILES.write_text(json.dumps(served, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    assert json.loads(_FILES.read_text(encoding="utf-8")) == served
