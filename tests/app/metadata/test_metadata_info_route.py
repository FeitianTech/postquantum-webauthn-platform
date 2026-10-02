"""GET /api/mds/metadata/info: what the MDS explorer starts from, as JSON.

The page asks for it when the MDS section is first shown.
"""
from __future__ import annotations

import io
import json
import os

from server.app.mds import files as mds_files
from tests.app.metadata import mds_fixture
from tests.app.metadata.snapshot_versions import snapshot_version


def _summary():
    return json.loads((mds_fixture.SNAPSHOT_DIR / mds_files.EXPLORER_META).read_text(encoding="utf-8"))


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
        "snapshotUrl": "/assets/mds/fido-mds3.explorer.list.json",
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
    # The namespace that answer minted holds nothing: the next page load is told so too.
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "none"

    client.get("/api/mds/metadata/explorer/full")
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "none"

    assert _upload(client).status_code == 200
    client.get("/api/mds/metadata/explorer/full")
    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "present"


def test_the_snapshot_url_is_the_explorer_list_revalidated_by_its_etag(mds_fixture_snapshot, client):
    url = client.get("/api/mds/metadata/info").get_json()["snapshotUrl"]

    assert url == "/assets/mds/fido-mds3.explorer.list.json"
    with client.get(url, headers={"Accept-Encoding": "identity"}) as listed:
        assert listed.status_code == 200
        assert listed.headers["Cache-Control"] == "no-cache"
        assert listed.headers["ETag"]
        assert json.loads(listed.data)["meta"]["no"] == 7


def test_a_new_snapshot_is_a_new_list_at_the_same_url(mds_fixture_snapshot, client):
    url = client.get("/api/mds/metadata/info").get_json()["snapshotUrl"]
    before = client.get(url).headers["ETag"]

    # A refresh writes every file whole, metas last (with times of their own).
    for step, (name, data) in enumerate(sorted(snapshot_version(8).items(), key=lambda item: item[0] in mds_files.META_FILENAMES)):
        path = mds_fixture_snapshot / name
        path.write_bytes(data)
        os.utime(path, (2_000_000_000 + step, 2_000_000_000 + step))

    assert client.get("/api/mds/metadata/info").get_json()["snapshotUrl"] == url
    with client.get(url, headers={"If-None-Match": before, "Accept-Encoding": "identity"}) as after:
        assert after.status_code == 200
        assert after.headers["ETag"] != before
        assert json.loads(after.data)["meta"]["no"] == 8


def test_without_a_snapshot_it_names_no_snapshot_url(client):
    # The page then asks the explorer API instead of requesting a missing file.
    assert client.get("/api/mds/metadata/info").get_json() == {"customEntriesState": "none"}


def test_without_the_browsers_file_it_names_no_snapshot_url(mds_fixture_snapshot, client):
    (mds_fixture_snapshot / mds_files.EXPLORER_FULL).unlink()

    answer = client.get("/api/mds/metadata/info").get_json()

    assert "snapshotUrl" not in answer
    assert answer["no"] == _summary()["no"]


def test_a_browsers_file_from_another_snapshot_is_not_named(mds_fixture_snapshot, client):
    # The API would answer from the verified snapshot; a file whose meta names
    # another one would show different entries, so the page is not sent to it.
    meta_path = mds_fixture_snapshot / mds_files.EXPLORER_FULL_META
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


def test_a_namespace_recovered_from_the_long_lived_cookie_may_hold_uploads(mds_fixture_snapshot, client):
    client.get("/api/mds/metadata/info")
    recovery = client.get_cookie("fido.mds.session")
    client.delete_cookie("session")
    client.set_cookie(recovery.key, recovery.value)

    assert client.get("/api/mds/metadata/info").get_json()["customEntriesState"] == "unknown"
