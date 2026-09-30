import io
import json
from datetime import datetime, timezone

import pytest

from server.app.routes import general as general_module
from tests.app.entry_app import entry_app


@pytest.fixture
def packaged_metadata_env(monkeypatch, tmp_path, metadata_state, blob):

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

    return blob


def test_packaged_metadata_loads_without_download(packaged_metadata_env):
    metadata, _ = packaged_metadata_env._load_base_metadata()
    assert metadata is not None
    assert metadata.entries == []


def test_metadata_not_available_is_warning_classical():
    from server.app.webauthn import attestation

    attestation_object = type("obj", (), {"att_stmt": {}})()
    attestation_result = type(
        "result",
        (),
        {"trust_path": [], "metadata_entry": None, "metadata_lookup_source": None},
    )()
    outcome = attestation._evaluate_classical_attestation_root(
        attestation_object,
        attestation_result,
        b"",
        None,
        datetime.now(timezone.utc),
    )

    assert "metadata_not_available" in outcome["warnings"]
    assert "metadata_not_available" not in outcome["errors"]
    assert "metadata_entry_missing" not in outcome["errors"]


def test_the_mds_info_answers_the_summary_and_the_custom_entries_state(monkeypatch, app_config):
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(general_module, "load_packaged_explorer_summary", lambda: {})
    monkeypatch.setattr(general_module, "load_packaged_snapshot_meta", lambda: None)

    with entry_app().test_request_context("/api/mds/metadata/info"):
        result = general_module._initial_mds_info()

    assert result == {"customEntriesState": "unknown"}


def test_full_explorer_metadata_route_sets_no_store_headers(monkeypatch, app_config):
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(
        general_module,
        "load_effective_full_snapshot",
        lambda: {"meta": {"entryCount": 1}, "entries": [{"entryId": "aaguid:test", "metadataStatement": {}}]},
    )

    with entry_app().test_client() as client:
        response = client.get("/api/mds/metadata/explorer/full")

    assert response.status_code == 200
    assert response.get_json()["meta"]["entryCount"] == 1
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Vary"] == "Cookie"


def test_resolve_metadata_entry_requires_exactly_one_lookup(monkeypatch, app_config):
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")

    with entry_app().test_client() as client:
        response = client.get("/api/mds/metadata/resolve")

    assert response.status_code == 400
    assert response.get_json()["error"] == "Provide exactly one of entryId, aaguid, or aaid."


def test_resolve_metadata_entry_returns_not_found(monkeypatch, app_config):
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(
        general_module,
        "resolve_effective_metadata_entry",
        lambda **_kwargs: None,
    )

    with entry_app().test_client() as client:
        response = client.get("/api/mds/metadata/resolve?aaguid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    assert response.status_code == 404
    assert response.get_json()["error"] == "Metadata entry not found."


def test_resolve_metadata_entry_returns_entry(monkeypatch, app_config):
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(
        general_module,
        "resolve_effective_metadata_entry",
        lambda **_kwargs: {"entryId": "aaguid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "name": "Demo"},
    )

    with entry_app().test_client() as client:
        response = client.get("/api/mds/metadata/resolve?aaguid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    assert response.status_code == 200
    assert response.get_json() == {
        "entry": {
            "entryId": "aaguid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "name": "Demo",
        }
    }


def test_upload_custom_metadata_returns_rebuilt_snapshot(monkeypatch, app_config):
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(
        general_module,
        "expand_metadata_entry_payloads",
        lambda payload: [payload],
    )
    monkeypatch.setattr(general_module, "maybe_store_uploaded_metadata_file", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        general_module,
        "save_session_metadata_item",
        lambda payload, original_filename=None: {"payload": payload, "original_filename": original_filename},
    )
    monkeypatch.setattr(
        general_module,
        "serialize_session_metadata_item",
        lambda item: {"storedFilename": "custom.json", "originalFilename": item["original_filename"]},
    )
    monkeypatch.setattr(
        general_module,
        "load_effective_full_snapshot",
        lambda: {"meta": {"entryCount": 1}, "entries": [{"entryId": "aaguid:test"}]},
    )

    with entry_app().test_client() as client:
        response = client.post(
            "/api/mds/metadata/upload",
            data={"files": (io.BytesIO(b'{"metadataStatement":{"description":"Demo"}}'), "custom.json")},
            content_type="multipart/form-data",
        )

    assert response.status_code == 200
    assert response.get_json()["snapshot"]["meta"]["entryCount"] == 1


def test_delete_custom_metadata_returns_rebuilt_snapshot(monkeypatch, app_config):
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(general_module, "delete_session_metadata_item", lambda _name: True)
    monkeypatch.setattr(
        general_module,
        "load_effective_full_snapshot",
        lambda: {"meta": {"entryCount": 3}, "entries": [{"entryId": "aaguid:test"}]},
    )

    with entry_app().test_client() as client:
        response = client.delete("/api/mds/metadata/custom/custom.json")

    assert response.status_code == 200
    assert response.get_json()["snapshot"]["meta"]["entryCount"] == 3
