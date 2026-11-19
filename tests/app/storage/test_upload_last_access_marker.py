"""A metadata upload marks its namespace's last access once, however many entries it saves.

Cloud Storage takes about one write a second to one object name, so a marker written
for each entry would hold an upload of the whole MDS metadata for many minutes. The
sweep of idle namespaces must still find a namespace just uploaded to in use.
"""

from __future__ import annotations

import io
import json
import os
import time

import pytest

from server.app import visitor_session
from server.app.mds import uploads as mds_uploads
from server.app.storage import session_metadata
from tests.app.metadata.upload_entries import minimal_entry
from tests.app.storage import fake_gcs

ENTRIES = 4


@pytest.fixture(params=["local", "gcs"])
def marker_writes(request, monkeypatch, own_stores, mds_fixture_snapshot):
    """Every write of a namespace's ``.last-access`` marker, on the backend the test runs on."""

    if request.param == "gcs":
        bucket = fake_gcs.install(monkeypatch, session_metadata)

        def _written() -> list[str]:
            return [name for name in bucket.writes if name.endswith("/.last-access")]

        return _written

    written: list[str] = []
    utime = os.utime

    def _utime(path, *args, **kwargs):
        if os.path.basename(path) == ".last-access":
            written.append(path)
        return utime(path, *args, **kwargs)

    monkeypatch.setattr(os, "utime", _utime)
    return lambda: list(written)


def _upload(client, count: int = ENTRIES):
    body = json.dumps({"entries": [minimal_entry(f"Entry {index}") for index in range(count)]}).encode()
    return client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(body), "entries.json")},
        content_type="multipart/form-data",
    )


def _namespace() -> str:
    (namespace,) = session_metadata.list_sessions()
    return namespace


def test_an_upload_of_several_entries_writes_its_namespaces_marker_once(marker_writes, client):
    response = _upload(client)

    assert response.status_code == 200, response.get_json()
    assert len(response.get_json()["items"]) == ENTRIES
    assert len(marker_writes()) == 1


def test_the_sweep_keeps_a_namespace_just_uploaded_to_by_its_marker(marker_writes, client):
    before = time.time() - 1

    assert _upload(client).status_code == 200
    namespace = _namespace()
    visitor_session._maybe_cleanup(now=time.time())

    assert session_metadata.list_sessions() == [namespace]
    assert marker_writes()
    assert session_metadata.resolve_last_access(namespace) >= before


def test_an_upload_that_fails_part_way_leaves_its_namespace_marked_and_kept(marker_writes, client, monkeypatch):
    save = mds_uploads.save_session_metadata_item
    saved = []

    def _save_one_then_fail(*args, **kwargs):
        if saved:
            raise RuntimeError("the store stopped")
        saved.append(save(*args, **kwargs))
        return saved[-1]

    monkeypatch.setattr(mds_uploads, "save_session_metadata_item", _save_one_then_fail)
    before = time.time() - 1

    assert _upload(client).status_code == 500
    namespace = _namespace()
    visitor_session._maybe_cleanup(now=time.time())

    assert session_metadata.list_sessions() == [namespace]
    assert len(marker_writes()) == 1
    assert session_metadata.resolve_last_access(namespace) >= before
