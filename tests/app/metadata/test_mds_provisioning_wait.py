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

from server.app.config.web_export import WEB_EXPORT_ROOT_KEY
from server.app.mds import provisioning as mds_provisioning
from server.app.storage import github_mirror
from tests.app.metadata import mds_fixture
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    Authenticator,
    advanced_public_key_options,
    registration_payload,
    unb64u,
)
from tests.app.storage import fake_gcs

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

    def download(_blob_name):
        downloading.set()
        release.wait(10)

    monkeypatch.delenv("FIDO_SERVER_MDS_GCS_PREFIX", raising=False)
    monkeypatch.setattr(mds_provisioning.cloud, "gcs_enabled", lambda: True)
    bucket = fake_gcs.install(monkeypatch)
    for name in mds_provisioning.SNAPSHOT_FILENAMES:
        bucket.put(f"mds/{name}", (mds_fixture.SNAPSHOT_DIR / name).read_bytes())
    bucket.on_download.append(download)

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


def test_the_explorer_list_waits_and_then_is_served(slow_provisioning, client):
    thread, answer = _get_in_a_thread(client, "/assets/mds/fido-mds3.explorer.list.json")
    try:
        thread.join(0.2)
        assert thread.is_alive()
    finally:
        slow_provisioning.set()
        thread.join(10)
    with answer["response"] as response:
        assert response.status_code == 200


def test_the_page_does_not_wait(slow_provisioning, make_app, export_root):
    client = make_app({WEB_EXPORT_ROOT_KEY: str(export_root)}).test_client()
    thread, answer = _get_in_a_thread(client, "/")
    thread.join(5)

    assert not thread.is_alive(), "the page waited for the provisioning"
    assert answer["response"].status_code == 200


# -- a registration's own lookup of its authenticator --------------------------------
#
# Registration complete looks the new credential's AAGUID up in the snapshot (the
# attestation checks' root validation and metadata entry) and records what it found
# in the credential for good: answered during a cold provisioning, it would record
# that no metadata was available.


@pytest.fixture
def stores(monkeypatch, tmp_path):
    """Every store a registration writes, in this test's own directory."""


    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(tmp_path / "credentials"))
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda _event: None)


def _post_in_a_thread(client, path, body):
    answer = {}
    thread = threading.Thread(
        target=lambda: answer.setdefault("response", client.post(path, json=body, headers={"Origin": ORIGIN})),
        daemon=True,
    )
    thread.start()
    return thread, answer


def _registration_waits_until_released(client, path, body, release):
    thread, answer = _post_in_a_thread(client, path, body)
    try:
        thread.join(0.2)
        assert thread.is_alive(), f"{path} answered before the snapshot was provisioned"
    finally:
        release.set()
        thread.join(10)
    assert not thread.is_alive()
    return answer["response"]


def _fixture_authenticator():
    return Authenticator(credential_id=b"\x07" * 32, aaguid=bytes.fromhex(AAGUID.replace("-", "")))


def test_a_simple_registration_waits_and_then_finds_its_authenticator(slow_provisioning, stores, client):
    begin = client.post("/api/register/begin?email=user@example.com", json={"credentials": []})
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    response = _registration_waits_until_released(
        client,
        "/api/register/complete?email=user@example.com",
        registration_payload(_fixture_authenticator(), challenge=challenge),
        slow_provisioning,
    )

    assert response.status_code == 200, response.get_json()
    summary = response.get_json()["storedCredential"]["properties"]["attestationSummary"]
    assert summary["metadata"]["available"] is True
    assert "metadata_not_available" not in summary.get("warnings", [])


def test_an_advanced_registration_waits_and_then_finds_its_authenticator(slow_provisioning, stores, client):
    options = advanced_public_key_options(challenge=b"\x11" * 32)
    begin = client.post("/api/advanced/register/begin", json={"publicKey": options})
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    response = _registration_waits_until_released(
        client,
        "/api/advanced/register/complete",
        {"publicKey": options, "__credential_response": registration_payload(_fixture_authenticator(), challenge=challenge)},
        slow_provisioning,
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["attestationSummary"]["metadata"]["available"] is True
