"""GET /api/mds/metadata/info: what the MDS explorer starts from, as JSON.

The new UI at /beta asks for what the current UI's index inlines as
``initial-mds-info``; one function builds both.
"""
from __future__ import annotations

import io
import json
import re

from server.app import mds_snapshot_dir
from server.app.static_assets import asset_url
from tests.app.metadata import mds_fixture

_INLINE = re.compile(r'<script type="application/json" id="initial-mds-info">(.*?)</script>', re.S)


def _summary():
    return json.loads((mds_fixture.SNAPSHOT_DIR / mds_snapshot_dir.EXPLORER_META).read_text(encoding="utf-8"))


def _upload(client):
    return client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(mds_fixture.CUSTOM_METADATA_PATH.read_bytes()), "custom-metadata.json")},
        content_type="multipart/form-data",
    )


def test_a_new_session_gets_the_packaged_summary_and_the_static_snapshot(mds_fixture_snapshot, client):
    answer = client.get("/api/mds/metadata/info")

    assert answer.status_code == 200
    assert answer.get_json() == {
        **_summary(),
        "snapshotUrl": asset_url("fido-mds3.explorer.full.json"),
        "customEntriesState": "none",
    }
    assert client.get_cookie("session") is not None
    assert client.get_cookie("fido.mds.session") is not None


def test_the_answer_is_per_session_and_never_cached(mds_fixture_snapshot, client):
    answer = client.get("/api/mds/metadata/info")

    assert answer.headers["Cache-Control"] == "no-store"
    assert "Cookie" in answer.headers["Vary"]


def test_it_is_what_the_index_inlines(mds_fixture_snapshot, make_app):
    index = make_app().test_client().get("/")
    inlined = json.loads(_INLINE.search(index.get_data(as_text=True)).group(1))

    assert make_app().test_client().get("/api/mds/metadata/info").get_json() == inlined


def test_a_known_session_says_what_its_last_explorer_answer_held(mds_fixture_snapshot, client):
    client.get("/api/mds/metadata/info")
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "unknown"

    client.get("/api/mds/metadata/explorer/full")
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "none"

    assert _upload(client).status_code == 200
    client.get("/api/mds/metadata/explorer/full")
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "present"


def test_without_a_snapshot_it_still_names_the_snapshot_url(client):
    assert client.get("/api/mds/metadata/info").get_json() == {
        "snapshotUrl": asset_url("fido-mds3.explorer.full.json"),
        "customEntriesState": "none",
    }


def test_only_get_is_answered(client):
    assert client.post("/api/mds/metadata/info").status_code == 405
