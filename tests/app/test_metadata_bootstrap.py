from datetime import datetime, timezone
import json

import pytest


@pytest.fixture
def packaged_metadata_env(monkeypatch, tmp_path):
    general_module = pytest.importorskip("server.app.routes.general")
    metadata_module = pytest.importorskip("server.app.metadata")

    verified_path = tmp_path / "fido-mds3.verified.json"
    cache_path = tmp_path / "fido-mds3.verified.json.meta.json"

    payload = {
        "legalHeader": "test header",
        "no": 1,
        "nextUpdate": "2099-01-01",
        "entries": [],
    }
    verified_path.write_text(json.dumps(payload), encoding="utf-8")
    cache_path.write_text(
        json.dumps(
            {
                "last_modified": None,
                "last_modified_iso": None,
                "etag": None,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(metadata_module, "MDS_METADATA_VERIFIED_PATH", str(verified_path), raising=False)
    monkeypatch.setattr(metadata_module, "MDS_METADATA_CACHE_PATH", str(cache_path), raising=False)
    monkeypatch.setattr(general_module, "MDS_METADATA_VERIFIED_PATH", str(verified_path), raising=False)

    # Reset cached state.
    monkeypatch.setattr(metadata_module, "_base_metadata_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_mtime", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_source", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_verifier_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_verifier_mtime", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_trust_verified", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_entry_ids", set(), raising=False)

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
    monkeypatch.setattr(general_module, "load_metadata_cache_entry", lambda: {}, raising=False)
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
    monkeypatch.setattr(general_module, "load_metadata_cache_entry", lambda: {}, raising=False)
    monkeypatch.setattr(general_module, "render_template", lambda *_args, **_kwargs: "ok", raising=False)

    with config_module.app.test_request_context("/index.html"):
        result = general_module.index_html()

    assert result == "ok"
    assert bootstrap_calls == [{"skip_if_reloader_parent": False}]


def test_mds_fragment_route_is_served(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")

    rendered = {}

    def _render_template(name, *_args, **_kwargs):
        rendered["name"] = name
        return "mds-fragment"

    monkeypatch.setattr(general_module, "render_template", _render_template, raising=False)

    with config_module.app.test_client() as client:
        response = client.get("/templates/advanced/mds-content.html")

    assert response.status_code == 200
    assert response.data == b"mds-fragment"
    assert rendered.get("name") == "advanced/mds-content.html"
