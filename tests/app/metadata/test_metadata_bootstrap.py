import json
from datetime import datetime, timezone

import pytest

from server.app import visitor_session
from server.app.mds import cache as mds_cache
from tests.app.entry_app import entry_app


@pytest.fixture
def packaged_metadata_env(monkeypatch, tmp_path, metadata_state):

    verified_path = tmp_path / "fido-mds3.verified.json"
    cache_path = tmp_path / "fido-mds3.verified.json.meta.json"
    explorer_path = tmp_path / "fido-mds3.explorer.json"

    payload = {
        "legalHeader": "test header",
        "no": 1,
        "nextUpdate": "2099-01-01",
        "entries": [],
    }
    explorer_payload = {
        "meta": {
            "entryCount": 0,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "legalHeader": "test header",
            "nextUpdate": "2099-01-01",
            "no": 1,
            "source": "packaged",
        },
        "entries": [],
    }
    verified_path.write_text(json.dumps(payload), encoding="utf-8")
    explorer_path.write_text(json.dumps(explorer_payload), encoding="utf-8")
    cache_path.write_text(
        json.dumps(
            {
                "last_modified": None,
                "last_modified_iso": None,
                "etag": None,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "no": 1,
                "nextUpdate": "2099-01-01",
                "entryCount": 0,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))


def test_packaged_metadata_loads_without_download(packaged_metadata_env):
    assert mds_cache.load_verified_entries() == []


def test_resolve_metadata_entry_requires_exactly_one_lookup(monkeypatch):
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")

    with entry_app().test_client() as client:
        response = client.get("/api/mds/metadata/resolve")

    assert response.status_code == 400
    assert response.get_json()["error"] == "Provide exactly one of entryId, aaguid, or aaid."
