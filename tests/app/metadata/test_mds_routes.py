"""The MDS routes that only read give a visitor without a namespace none."""
from __future__ import annotations

import io
import json

import pytest

from server.app.storage import session_metadata
from tests.app.metadata.upload_entries import minimal_entry


@pytest.fixture(autouse=True)
def _own_namespaces(monkeypatch, tmp_path):
    """This test's own uploads store, so the namespaces listed are only the ones it made."""

    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))


_READS = [
    ("GET", "/api/mds/metadata/info", 200),
    ("GET", "/api/mds/metadata/explorer/full", 200),
    ("GET", "/api/mds/metadata/resolve?aaguid=f1d0f1d0-0000-4000-8000-000000000001", 200),
    ("GET", "/api/mds/metadata/custom", 200),
    ("DELETE", "/api/mds/metadata/custom/0123456789abcdef.json", 404),
]


@pytest.mark.parametrize(("method", "path", "status"), _READS)
def test_a_read_mints_no_namespace_and_sets_no_cookie(mds_fixture_snapshot, client, method, path, status):
    response = client.open(path, method=method)

    assert response.status_code == status
    assert response.headers.getlist("Set-Cookie") == []
    assert session_metadata.list_sessions() == []


def test_an_upload_still_mints_the_namespace_it_is_stored_under(mds_fixture_snapshot, client):
    response = client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(json.dumps(minimal_entry("Uploaded")).encode()), "entry.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200, response.get_json()
    assert client.get_cookie("fido.mds.session") is not None
    assert len(session_metadata.list_sessions()) == 1


def test_the_visitors_uploads_are_never_cached_and_keyed_on_the_cookie(mds_fixture_snapshot, client):
    response = client.get("/api/mds/metadata/custom")

    assert response.headers["Cache-Control"] == "no-store"
    assert "Cookie" in response.headers["Vary"]


def test_the_full_explorer_is_never_cached_and_keyed_on_the_cookie(mds_fixture_snapshot, client):
    response = client.get("/api/mds/metadata/explorer/full")

    assert response.status_code == 200
    assert len(response.get_json()["entries"]) == 32
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Vary"] == "Cookie"


def test_an_aaguid_no_entry_has_is_not_found(mds_fixture_snapshot, client):
    response = client.get("/api/mds/metadata/resolve?aaguid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    assert response.status_code == 404
    assert response.get_json() == {"error": "Metadata entry not found."}
