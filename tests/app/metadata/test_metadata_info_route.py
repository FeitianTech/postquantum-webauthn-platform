"""GET /api/mds/metadata/info: what the MDS explorer starts from, as JSON.

The page asks for it when the MDS section is first shown.
"""
from __future__ import annotations

import hashlib
import io
import json

from server.app import mds_snapshot_dir
from server.app.routes.assets import asset_url
from tests.app.metadata import mds_fixture


def _summary():
    return json.loads((mds_fixture.SNAPSHOT_DIR / mds_snapshot_dir.EXPLORER_META).read_text(encoding="utf-8"))


def _upload(client):
    return client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(mds_fixture.CUSTOM_METADATA_PATH.read_bytes()), "custom-metadata.json")},
        content_type="multipart/form-data",
    )


def _version(meta):
    digest = hashlib.sha256(json.dumps([meta["etag"], meta["generatedAt"]]).encode("utf-8")).hexdigest()[:12]
    return f"{meta['no']}.{digest}"


def test_a_new_session_gets_the_packaged_summary_and_the_static_snapshot(mds_fixture_snapshot, client):
    answer = client.get("/api/mds/metadata/info")

    assert answer.status_code == 200
    assert answer.get_json() == {
        **_summary(),
        "snapshotUrl": f"{asset_url('fido-mds3.explorer.full.json')}?v={_version(_summary())}",
        "customEntriesState": "none",
    }
    assert client.get_cookie("session") is not None
    assert client.get_cookie("fido.mds.session") is not None


def test_the_answer_is_per_session_and_never_cached(mds_fixture_snapshot, client):
    answer = client.get("/api/mds/metadata/info")

    assert answer.headers["Cache-Control"] == "no-store"
    assert "Cookie" in answer.headers["Vary"]


def test_a_known_session_says_what_its_last_explorer_answer_held(mds_fixture_snapshot, client):
    client.get("/api/mds/metadata/info")
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "unknown"

    client.get("/api/mds/metadata/explorer/full")
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "none"

    assert _upload(client).status_code == 200
    client.get("/api/mds/metadata/explorer/full")
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "present"


def test_the_snapshot_url_names_the_snapshots_version_and_is_cached_for_good(mds_fixture_snapshot, client):
    url = client.get("/api/mds/metadata/info").get_json()["snapshotUrl"]

    assert url.endswith("?v=7." + url.rsplit(".", 1)[1])
    assert len(url.rsplit(".", 1)[1]) == 12
    with client.get(url) as static:
        assert static.status_code == 200
        assert static.headers["Cache-Control"] == "public, max-age=31536000, immutable"
        assert static.data == (mds_fixture_snapshot / mds_snapshot_dir.EXPLORER_FULL).read_bytes()


def test_a_new_snapshot_is_a_new_url(mds_fixture_snapshot, client):
    before = client.get("/api/mds/metadata/info").get_json()["snapshotUrl"]

    # A refresh writes every file again: the same serial, a new ETag and time.
    for name, key in (
        (mds_snapshot_dir.EXPLORER_FULL_META, "generatedAt"),
        (mds_snapshot_dir.EXPLORER_META, "generatedAt"),
        (mds_snapshot_dir.VERIFIED_META, "generated_at"),
    ):
        path = mds_fixture_snapshot / name
        meta = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps({**meta, "etag": '"fixture-8"', key: "2026-09-27T08:00:00+00:00"}), encoding="utf-8")

    after = client.get("/api/mds/metadata/info").get_json()["snapshotUrl"]
    assert after != before
    assert after.split("?")[0] == before.split("?")[0]


def test_without_a_snapshot_it_names_no_snapshot_url(client):
    # The page then asks the explorer API instead of requesting a missing file.
    assert client.get("/api/mds/metadata/info").get_json() == {"customEntriesState": "none"}


def test_without_the_browsers_file_it_names_no_snapshot_url(mds_fixture_snapshot, client):
    (mds_fixture_snapshot / mds_snapshot_dir.EXPLORER_FULL).unlink()

    answer = client.get("/api/mds/metadata/info").get_json()

    assert "snapshotUrl" not in answer
    assert answer["no"] == _summary()["no"]


def test_a_browsers_file_from_another_snapshot_is_not_named(mds_fixture_snapshot, client):
    # The API would answer from the verified snapshot; a file whose meta names
    # another one would show different entries, so the page is not sent to it.
    meta_path = mds_fixture_snapshot / mds_snapshot_dir.EXPLORER_FULL_META
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta_path.write_text(json.dumps({**meta, "etag": '"another"'}), encoding="utf-8")

    assert "snapshotUrl" not in client.get("/api/mds/metadata/info").get_json()


def test_only_get_is_answered(client):
    assert client.post("/api/mds/metadata/info").status_code == 405


def test_an_upload_and_a_delete_record_whether_the_session_has_uploads(mds_fixture_snapshot, client):
    # The session last saw no uploads: its page may load the packaged snapshot.
    client.get("/api/mds/metadata/explorer/full")
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "none"

    # After an upload a reload must ask the session's own list, not the packaged one.
    assert _upload(client).status_code == 200
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "present"

    stored = client.get("/api/mds/metadata/custom").get_json()["items"][0]["source"]["storedFilename"]
    assert client.delete(f"/api/mds/metadata/custom/{stored}").status_code == 200
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "none"
