"""A cold instance's MDS endpoints wait for the snapshot's provisioning.

On Cloud Run the snapshot is provisioned in the background when a worker starts
(``startup.start_background_warmup``), about 20 s from Cloud Storage. The routes
that read it wait for that provisioning rather than answer, meanwhile, as if
there were no snapshot; the index page does not wait, so a cold instance's first
page is not held (its explorer then asks the API, which waits).
"""
from __future__ import annotations

import threading

import pytest

from server.app import mds_provisioning
from tests.app.metadata import mds_fixture

AAGUID = "f1d0f1d0-0000-4000-8000-000000000001"
FIXTURE_ENTRIES = 32


@pytest.fixture
def slow_provisioning(monkeypatch, tmp_path, metadata_state):
    """A warm-up thread provisioning the fixture snapshot from a Cloud Storage that
    answers only once the test releases it. Yields the release."""

    target = tmp_path / "mds-snapshot"
    target.mkdir()
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(target))
    monkeypatch.setattr(mds_provisioning, "_provision_state", {"attempted": False, "source": None})
    monkeypatch.setattr(mds_provisioning, "_provision_lock", threading.Lock())

    downloading = threading.Event()
    release = threading.Event()

    def download(blob_name):
        downloading.set()
        release.wait(10)
        return (mds_fixture.SNAPSHOT_DIR / blob_name.rsplit("/", 1)[-1]).read_bytes()

    monkeypatch.setattr(mds_provisioning.cloud, "gcs_enabled", lambda: True)
    monkeypatch.setattr(mds_provisioning.cloud, "download_bytes", download)

    warmup = threading.Thread(target=mds_provisioning.ensure_snapshot_available, daemon=True)
    warmup.start()
    try:
        assert downloading.wait(5), "the warm-up never started provisioning"
        yield release
    finally:
        # Never leave the process-wide provisioning lock held for later tests.
        release.set()
        warmup.join(10)
        assert not warmup.is_alive()


def _get_in_a_thread(client, path):
    answer = {}
    thread = threading.Thread(target=lambda: answer.setdefault("response", client.get(path)), daemon=True)
    thread.start()
    return thread, answer


def _waits_until_released(client, path, release):
    thread, answer = _get_in_a_thread(client, path)
    try:
        thread.join(0.2)
        assert thread.is_alive(), f"{path} answered before the snapshot was provisioned"
    finally:
        release.set()
        thread.join(10)
    assert not thread.is_alive()
    return answer["response"]


def test_the_info_waits_and_then_offers_the_packaged_snapshot(slow_provisioning, client):
    response = _waits_until_released(client, "/api/mds/metadata/info", slow_provisioning)

    assert response.status_code == 200
    info = response.get_json()
    assert info["entryCount"] == FIXTURE_ENTRIES
    assert "snapshotUrl" in info


def test_the_explorer_waits_and_then_answers_every_entry(slow_provisioning, client):
    response = _waits_until_released(client, "/api/mds/metadata/explorer/full", slow_provisioning)

    assert response.status_code == 200
    assert len(response.get_json()["entries"]) == FIXTURE_ENTRIES


def test_resolve_waits_and_then_finds_the_entry(slow_provisioning, client):
    response = _waits_until_released(client, f"/api/mds/metadata/resolve?aaguid={AAGUID}", slow_provisioning)

    assert response.status_code == 200
    assert response.get_json()["entry"]["aaguid"] == AAGUID


def test_the_browsers_snapshot_file_waits_and_then_is_served(slow_provisioning, client):
    thread, answer = _get_in_a_thread(client, "/assets/dev/fido-mds3.explorer.full.json")
    try:
        thread.join(0.2)
        assert thread.is_alive()
    finally:
        slow_provisioning.set()
        thread.join(10)
    with answer["response"] as response:
        assert response.status_code == 200


def test_the_index_page_does_not_wait(slow_provisioning, client, monkeypatch):
    from server.app.routes import general

    monkeypatch.setattr(general, "_should_bootstrap_metadata_on_index", lambda: False)
    thread, answer = _get_in_a_thread(client, "/")
    thread.join(5)

    assert not thread.is_alive(), "the index waited for the provisioning"
    assert answer["response"].status_code == 200
    assert '"snapshotUrl"' not in answer["response"].get_data(as_text=True)
