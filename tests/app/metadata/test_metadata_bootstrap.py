import io
import json
from datetime import datetime, timezone

import pytest


@pytest.fixture
def packaged_metadata_env(monkeypatch, tmp_path, metadata_state, blob):
    general_module = pytest.importorskip("server.app.routes.general")
    metadata_module = pytest.importorskip("server.app.webauthn.metadata")

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

    # Reset cached state.

    monkeypatch.setattr(
        general_module,
        "_metadata_bootstrap_state",
        {"started": False, "completed": False, "marker": None, "cache_loaded": False},
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


def test_metadata_not_available_is_warning_pqc():
    from server.app.webauthn import attestation

    attestation_object = type("obj", (), {"att_stmt": {}})()
    outcome = attestation._evaluate_mldsa_attestation_root(
        attestation_object,
        b"",
        None,
        datetime.now(timezone.utc),
    )

    assert "metadata_not_available" in outcome["warnings"]
    assert "metadata_not_available" not in outcome["errors"]


def test_the_mds_info_skips_eager_bootstrap_by_default(monkeypatch, app_config):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    bootstrap_calls = []

    monkeypatch.delenv("FIDO_SERVER_EAGER_MDS_INFO_BOOTSTRAP", raising=False)
    monkeypatch.delenv("FIDO_SERVER_EAGER_INDEX_METADATA_BOOTSTRAP", raising=False)
    monkeypatch.setattr(
        general_module,
        "startup_fail_fast_enabled",
        lambda: False,
    )
    monkeypatch.setattr(
        general_module,
        "ensure_metadata_bootstrapped",
        lambda **kwargs: bootstrap_calls.append(kwargs),
    )
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(general_module, "load_packaged_explorer_summary", lambda: {})
    monkeypatch.setattr(general_module, "load_packaged_snapshot_meta", lambda: None)

    with config_module.app.test_request_context("/api/mds/metadata/info"):
        result = general_module._initial_mds_info()

    assert result == {"customEntriesState": "unknown"}
    assert bootstrap_calls == []


@pytest.mark.parametrize(
    ("settings", "fail_fast", "expected"),
    [
        ({"FIDO_SERVER_EAGER_MDS_INFO_BOOTSTRAP": "1"}, False, True),
        ({"FIDO_SERVER_EAGER_MDS_INFO_BOOTSTRAP": "0"}, True, False),
        ({"FIDO_SERVER_EAGER_INDEX_METADATA_BOOTSTRAP": "1"}, False, True),
        ({"FIDO_SERVER_EAGER_INDEX_METADATA_BOOTSTRAP": "off"}, True, False),
        ({"FIDO_SERVER_EAGER_MDS_INFO_BOOTSTRAP": "0", "FIDO_SERVER_EAGER_INDEX_METADATA_BOOTSTRAP": "1"}, False, False),
        ({"FIDO_SERVER_EAGER_MDS_INFO_BOOTSTRAP": "yes", "FIDO_SERVER_EAGER_INDEX_METADATA_BOOTSTRAP": "0"}, False, True),
        ({}, True, True),
        ({}, False, False),
    ],
)
def test_the_mds_info_bootstrap_setting_and_its_earlier_name(monkeypatch, settings, fail_fast, expected):
    general_module = pytest.importorskip("server.app.routes.general")

    for name in ("FIDO_SERVER_EAGER_MDS_INFO_BOOTSTRAP", "FIDO_SERVER_EAGER_INDEX_METADATA_BOOTSTRAP"):
        monkeypatch.delenv(name, raising=False)
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(general_module, "startup_fail_fast_enabled", lambda: fail_fast)

    assert general_module._should_bootstrap_metadata_for_info() is expected


def test_the_mds_info_bootstraps_when_strict(monkeypatch, app_config):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    bootstrap_calls = []

    monkeypatch.delenv("FIDO_SERVER_EAGER_MDS_INFO_BOOTSTRAP", raising=False)
    monkeypatch.delenv("FIDO_SERVER_EAGER_INDEX_METADATA_BOOTSTRAP", raising=False)
    monkeypatch.setattr(
        general_module,
        "startup_fail_fast_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        general_module,
        "ensure_metadata_bootstrapped",
        lambda **kwargs: bootstrap_calls.append(kwargs),
    )
    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(general_module, "load_packaged_explorer_summary", lambda: {})
    monkeypatch.setattr(general_module, "load_packaged_snapshot_meta", lambda: None)

    with config_module.app.test_request_context("/api/mds/metadata/info"):
        result = general_module._initial_mds_info()

    assert result == {"customEntriesState": "unknown"}
    assert bootstrap_calls == [{"skip_if_reloader_parent": False}]


def test_explorer_metadata_route_sets_no_store_headers(monkeypatch, app_config):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(
        general_module,
        "load_effective_explorer_snapshot",
        lambda: {"meta": {"entryCount": 1}, "entries": [{"entryId": "aaguid:test"}]},
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/mds/metadata/explorer")

    assert response.status_code == 200
    assert response.get_json() == {"meta": {"entryCount": 1}, "entries": [{"entryId": "aaguid:test"}]}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Vary"] == "Cookie"


def test_full_explorer_metadata_route_sets_no_store_headers(monkeypatch, app_config):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(
        general_module,
        "load_effective_full_snapshot",
        lambda: {"meta": {"entryCount": 1}, "entries": [{"entryId": "aaguid:test", "metadataStatement": {}}]},
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/mds/metadata/explorer/full")

    assert response.status_code == 200
    assert response.get_json()["meta"]["entryCount"] == 1
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Vary"] == "Cookie"


def test_resolve_metadata_entry_requires_exactly_one_lookup(monkeypatch, app_config):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")

    with config_module.app.test_client() as client:
        response = client.get("/api/mds/metadata/resolve")

    assert response.status_code == 400
    assert response.get_json()["error"] == "Provide exactly one of entryId, aaguid, or aaid."


def test_resolve_metadata_entry_returns_not_found(monkeypatch, app_config):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(
        general_module,
        "resolve_effective_metadata_entry",
        lambda **_kwargs: None,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/mds/metadata/resolve?aaguid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    assert response.status_code == 404
    assert response.get_json()["error"] == "Metadata entry not found."


def test_resolve_metadata_entry_returns_entry(monkeypatch, app_config):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(
        general_module,
        "resolve_effective_metadata_entry",
        lambda **_kwargs: {"entryId": "aaguid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "name": "Demo"},
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


def test_upload_custom_metadata_returns_rebuilt_snapshot(monkeypatch, app_config):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

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

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/mds/metadata/upload",
            data={"files": (io.BytesIO(b'{"metadataStatement":{"description":"Demo"}}'), "custom.json")},
            content_type="multipart/form-data",
        )

    assert response.status_code == 200
    assert response.get_json()["snapshot"]["meta"]["entryCount"] == 1


def test_delete_custom_metadata_returns_rebuilt_snapshot(monkeypatch, app_config):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(general_module, "delete_session_metadata_item", lambda _name: True)
    monkeypatch.setattr(
        general_module,
        "load_effective_full_snapshot",
        lambda: {"meta": {"entryCount": 3}, "entries": [{"entryId": "aaguid:test"}]},
    )

    with config_module.app.test_client() as client:
        response = client.delete("/api/mds/metadata/custom/custom.json")

    assert response.status_code == 200
    assert response.get_json()["snapshot"]["meta"]["entryCount"] == 3


