from datetime import datetime, timezone
import gzip
import json
import io

import pytest


@pytest.fixture
def packaged_metadata_env(monkeypatch, tmp_path):
    general_module = pytest.importorskip("server.app.routes.general")
    metadata_module = pytest.importorskip("server.app.metadata")

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

    monkeypatch.setattr(metadata_module, "MDS_METADATA_VERIFIED_PATH", str(verified_path), raising=False)
    monkeypatch.setattr(metadata_module, "MDS_METADATA_CACHE_PATH", str(cache_path), raising=False)
    monkeypatch.setattr(metadata_module, "MDS_EXPLORER_PATH", str(explorer_path), raising=False)
    monkeypatch.setattr(general_module, "MDS_METADATA_VERIFIED_PATH", str(verified_path), raising=False)

    # Reset cached state.
    monkeypatch.setattr(metadata_module, "_base_metadata_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_mtime", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_source", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_verifier_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_verifier_mtime", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_trust_verified", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_entry_ids", set(), raising=False)
    monkeypatch.setattr(metadata_module, "_base_explorer_snapshot_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_explorer_snapshot_mtime", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_full_snapshot_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_full_snapshot_mtime", None, raising=False)

    monkeypatch.setattr(
        general_module,
        "_metadata_bootstrap_state",
        {"started": False, "completed": False, "marker": None, "cache_loaded": False},
        raising=False,
    )

    return general_module, metadata_module


def test_packaged_metadata_bootstraps_without_download(packaged_metadata_env):
    general_module, metadata_module = packaged_metadata_env

    general_module.ensure_metadata_bootstrapped(skip_if_reloader_parent=False)

    with general_module._metadata_bootstrap_lock:
        assert general_module._metadata_bootstrap_state["completed"] is True
        assert general_module._metadata_bootstrap_state["started"] is False

    metadata, _ = metadata_module._load_base_metadata()
    assert metadata is not None
    assert metadata.entries == []


def test_metadata_not_available_is_warning_classical():
    from server.app import attestation

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


def test_metadata_not_available_is_warning_pqc():
    from server.app import attestation

    attestation_object = type("obj", (), {"att_stmt": {}})()
    outcome = attestation._evaluate_mldsa_attestation_root(
        attestation_object,
        b"",
        None,
        datetime.now(timezone.utc),
    )

    assert "metadata_not_available" in outcome["warnings"]
    assert "metadata_not_available" not in outcome["errors"]


def test_index_html_skips_eager_bootstrap_by_default(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    bootstrap_calls = []

    monkeypatch.delenv("FIDO_SERVER_EAGER_INDEX_METADATA_BOOTSTRAP", raising=False)
    monkeypatch.setattr(
        general_module,
        "startup_fail_fast_enabled",
        lambda: False,
        raising=False,
    )
    monkeypatch.setattr(
        general_module,
        "ensure_metadata_bootstrapped",
        lambda **kwargs: bootstrap_calls.append(kwargs),
        raising=False,
    )
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(general_module, "load_packaged_explorer_summary", lambda: {}, raising=False)
    monkeypatch.setattr(general_module, "render_template", lambda *_args, **_kwargs: "ok", raising=False)

    with config_module.app.test_request_context("/index.html"):
        result = general_module.index_html()

    assert result == "ok"
    assert bootstrap_calls == []


def test_index_html_bootstraps_when_strict(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    bootstrap_calls = []

    monkeypatch.delenv("FIDO_SERVER_EAGER_INDEX_METADATA_BOOTSTRAP", raising=False)
    monkeypatch.setattr(
        general_module,
        "startup_fail_fast_enabled",
        lambda: True,
        raising=False,
    )
    monkeypatch.setattr(
        general_module,
        "ensure_metadata_bootstrapped",
        lambda **kwargs: bootstrap_calls.append(kwargs),
        raising=False,
    )
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(general_module, "load_packaged_explorer_summary", lambda: {}, raising=False)
    monkeypatch.setattr(general_module, "render_template", lambda *_args, **_kwargs: "ok", raising=False)

    with config_module.app.test_request_context("/index.html"):
        result = general_module.index_html()

    assert result == "ok"
    assert bootstrap_calls == [{"skip_if_reloader_parent": False}]


def test_explorer_metadata_route_sets_no_store_headers(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(
        general_module,
        "load_effective_explorer_snapshot",
        lambda: {"meta": {"entryCount": 1}, "entries": [{"entryId": "aaguid:test"}]},
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/mds/metadata/explorer")

    assert response.status_code == 200
    assert response.get_json() == {"meta": {"entryCount": 1}, "entries": [{"entryId": "aaguid:test"}]}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Vary"] == "Cookie"


def test_full_explorer_metadata_route_sets_no_store_headers(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(
        general_module,
        "load_effective_full_snapshot",
        lambda: {"meta": {"entryCount": 1}, "entries": [{"entryId": "aaguid:test", "metadataStatement": {}}]},
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/mds/metadata/explorer/full")

    assert response.status_code == 200
    assert response.get_json()["meta"]["entryCount"] == 1
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Vary"] == "Cookie"


def test_resolve_metadata_entry_requires_exactly_one_lookup(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)

    with config_module.app.test_client() as client:
        response = client.get("/api/mds/metadata/resolve")

    assert response.status_code == 400
    assert response.get_json()["error"] == "Provide exactly one of entryId, aaguid, or aaid."


def test_resolve_metadata_entry_returns_not_found(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(
        general_module,
        "resolve_effective_metadata_entry",
        lambda **_kwargs: None,
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/mds/metadata/resolve?aaguid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    assert response.status_code == 404
    assert response.get_json()["error"] == "Metadata entry not found."


def test_resolve_metadata_entry_returns_entry(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(
        general_module,
        "resolve_effective_metadata_entry",
        lambda **_kwargs: {"entryId": "aaguid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "name": "Demo"},
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/mds/metadata/resolve?aaguid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    assert response.status_code == 200
    assert response.get_json() == {
        "entry": {
            "entryId": "aaguid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "name": "Demo",
        }
    }


def test_index_page_emits_accessible_global_loader_markup(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(general_module, "load_packaged_explorer_summary", lambda: {"entryCount": 0}, raising=False)
    monkeypatch.setattr(general_module, "_should_bootstrap_metadata_on_index", lambda: False, raising=False)

    with config_module.app.test_client() as client:
        response = client.get("/index.html")

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'id="app-loader"' in body
    assert 'class="app-loader"' in body
    assert 'role="status"' in body
    assert 'aria-live="polite"' in body
    assert 'templates/advanced/mds-content.html' not in body
    assert 'fido-mds3.explorer.bootstrap.js' in body
    assert '__INITIAL_CREDENTIAL_RECORDS__' in body


def test_upload_custom_metadata_returns_rebuilt_snapshot(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(
        general_module,
        "expand_metadata_entry_payloads",
        lambda payload: [payload],
        raising=False,
    )
    monkeypatch.setattr(general_module, "maybe_store_uploaded_metadata_file", lambda *_args, **_kwargs: False, raising=False)
    monkeypatch.setattr(
        general_module,
        "save_session_metadata_item",
        lambda payload, original_filename=None: {"payload": payload, "original_filename": original_filename},
        raising=False,
    )
    monkeypatch.setattr(
        general_module,
        "serialize_session_metadata_item",
        lambda item: {"storedFilename": "custom.json", "originalFilename": item["original_filename"]},
        raising=False,
    )
    monkeypatch.setattr(
        general_module,
        "load_effective_full_snapshot",
        lambda: {"meta": {"entryCount": 1}, "entries": [{"entryId": "aaguid:test"}]},
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/mds/metadata/upload",
            data={"files": (io.BytesIO(b'{"metadataStatement":{"description":"Demo"}}'), "custom.json")},
            content_type="multipart/form-data",
        )

    assert response.status_code == 200
    assert response.get_json()["snapshot"]["meta"]["entryCount"] == 1


def test_delete_custom_metadata_returns_rebuilt_snapshot(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(general_module, "delete_session_metadata_item", lambda _name: True, raising=False)
    monkeypatch.setattr(
        general_module,
        "load_effective_full_snapshot",
        lambda: {"meta": {"entryCount": 3}, "entries": [{"entryId": "aaguid:test"}]},
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.delete("/api/mds/metadata/custom/custom.json")

    assert response.status_code == 200
    assert response.get_json()["snapshot"]["meta"]["entryCount"] == 3


def test_index_page_supports_gzip_compression(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(general_module, "load_packaged_explorer_summary", lambda: {"entryCount": 0}, raising=False)
    monkeypatch.setattr(general_module, "_should_bootstrap_metadata_on_index", lambda: False, raising=False)

    with config_module.app.test_client() as client:
        response = client.get("/index.html", headers={"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") == "gzip"
    assert "Accept-Encoding" in response.headers.get("Vary", "")
    body = gzip.decompress(response.data).decode("utf-8")
    assert "<!DOCTYPE html>" in body
