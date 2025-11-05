import json  # Needed to persist fake metadata cache snapshots in tests.
import threading  # Coordinates background refresh completion in tests.
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from server.server import attestation


@pytest.fixture
def metadata_test_env(monkeypatch, tmp_path):
    general_module = pytest.importorskip("server.server.routes.general")
    metadata_module = pytest.importorskip("server.server.metadata")

    metadata_path = tmp_path / "fido-mds3.jws"
    cache_path = tmp_path / "fido-mds3.jws.meta.json"
    verified_path = tmp_path / "fido-mds3.verified.json"

    load_calls = {"count": 0}

    def fake_load_cached_snapshot() -> bool:
        load_calls["count"] += 1
        return metadata_path.exists()

    monkeypatch.setattr(metadata_module, "MDS_METADATA_PATH", str(metadata_path), raising=False)
    monkeypatch.setattr(metadata_module, "MDS_METADATA_CACHE_PATH", str(cache_path), raising=False)
    monkeypatch.setattr(metadata_module, "MDS_METADATA_VERIFIED_PATH", str(verified_path), raising=False)
    monkeypatch.setattr(
        metadata_module,
        "load_cached_metadata_snapshot",
        fake_load_cached_snapshot,
        raising=False,
    )

    monkeypatch.setattr(general_module, "MDS_METADATA_PATH", str(metadata_path), raising=False)
    monkeypatch.setattr(general_module, "load_cached_metadata_snapshot", fake_load_cached_snapshot, raising=False)
    monkeypatch.setattr(general_module, "_metadata_refresh_thread", None, raising=False)
    monkeypatch.setattr(
        general_module,
        "_metadata_bootstrap_state",
        {"started": False, "completed": False, "marker": None, "cache_loaded": False},
        raising=False,
    )

    env_flag = general_module._METADATA_BOOTSTRAP_ENV_FLAG
    monkeypatch.setenv(env_flag, "")

    monkeypatch.setattr(metadata_module, "_base_metadata_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_mtime", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_source", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_verifier_cache", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_verifier_mtime", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_trust_verified", None, raising=False)
    monkeypatch.setattr(metadata_module, "_base_metadata_entry_ids", set(), raising=False)

    return general_module, metadata_module, metadata_path, cache_path, load_calls


def test_metadata_background_refresh_non_blocking(metadata_test_env, monkeypatch):
    general_module, _, metadata_path, cache_path, load_calls = metadata_test_env

    refresh_started = threading.Event()
    allow_finish = threading.Event()

    def fake_download_metadata_blob():
        refresh_started.set()
        if not allow_finish.wait(timeout=5):
            raise TimeoutError("Background refresh did not finish in time for the test.")

        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_payload = b"test-metadata"
        metadata_path.write_bytes(metadata_payload)

        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_payload = {
            "last_modified": "Wed, 01 Jan 2025 00:00:00 GMT",
            "last_modified_iso": "2025-01-01T00:00:00+00:00",
            "etag": "test-etag",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(cache_path, "w", encoding="utf-8") as cache_file:
            json.dump(cache_payload, cache_file)
        return True, len(metadata_payload), cache_payload["last_modified_iso"]

    monkeypatch.setattr(general_module, "download_metadata_blob", fake_download_metadata_blob, raising=False)

    general_module.ensure_metadata_bootstrapped(skip_if_reloader_parent=False)

    assert refresh_started.wait(timeout=1.5)

    with general_module.app.test_client() as client:
        response = client.get("/index.html")
        assert response.status_code == 200

    allow_finish.set()
    thread = general_module._metadata_refresh_thread
    if thread is not None:
        thread.join(timeout=5)

    deadline = time.time() + 5
    while time.time() < deadline:
        with general_module._metadata_bootstrap_lock:
            if general_module._metadata_bootstrap_state["completed"]:
                break
        time.sleep(0.05)

    with general_module._metadata_bootstrap_lock:
        assert general_module._metadata_bootstrap_state["completed"]

    assert metadata_path.exists()

    general_module.ensure_metadata_bootstrapped(skip_if_reloader_parent=False)
    assert load_calls["count"] >= 2

    with general_module._metadata_bootstrap_lock:
        assert general_module._metadata_bootstrap_state["cache_loaded"] is True


def test_metadata_not_available_is_warning_classical():
    attestation_object = SimpleNamespace(att_stmt={})
    attestation_result = SimpleNamespace(trust_path=[], metadata_entry=None, metadata_lookup_source=None)
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
    attestation_object = SimpleNamespace(att_stmt={})
    outcome = attestation._evaluate_mldsa_attestation_root(
        attestation_object,
        b"",
        None,
        datetime.now(timezone.utc),
    )

    assert "metadata_not_available" in outcome["warnings"]
    assert "metadata_not_available" not in outcome["errors"]
