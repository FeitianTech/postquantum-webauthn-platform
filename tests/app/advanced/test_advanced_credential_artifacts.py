import pytest


def test_bulk_credential_artifact_route_returns_requested_items(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)

    def _load(storage_id, *, session_id=None):
        assert session_id == "session-id"
        if storage_id == "cred-1":
            return {"registrationDetailSnapshot": {"html": "<p>ready</p>"}}
        return None

    monkeypatch.setattr(advanced_module, "load_credential_artifact", _load, raising=False)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/credential-artifacts/bulk",
            json={"storageIds": ["cred-1", "missing", "cred-1"]},
        )

    assert response.status_code == 200
    assert response.get_json() == {
        "artifacts": {
            "cred-1": {"registrationDetailSnapshot": {"html": "<p>ready</p>"}}
        }
    }


def test_bulk_credential_artifact_route_requires_array(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/credential-artifacts/bulk",
            json={"storageIds": "cred-1"},
        )

    assert response.status_code == 400
    assert response.get_json()["error"] == "storageIds must be an array."


def test_bulk_credential_artifact_route_trims_dedupes_and_ignores_invalid_ids(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)

    observed_storage_ids = []

    def _load(storage_id, *, session_id=None):
        assert session_id == "session-id"
        observed_storage_ids.append(storage_id)
        if storage_id == "cred-1":
            return {"storedCredential": {"id": "cred-1"}}
        if storage_id == "cred-2":
            return {"storedCredential": {"id": "cred-2"}}
        return None

    monkeypatch.setattr(advanced_module, "load_credential_artifact", _load, raising=False)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/credential-artifacts/bulk",
            json={
                "storageIds": ["  cred-1  ", "", "   ", None, 123, "cred-2", "cred-1"],
            },
        )

    assert response.status_code == 200
    assert observed_storage_ids == ["cred-1", "cred-2"]
    assert response.get_json() == {
        "artifacts": {
            "cred-1": {"storedCredential": {"id": "cred-1"}},
            "cred-2": {"storedCredential": {"id": "cred-2"}},
        }
    }


def test_get_credential_artifact_route_returns_payload(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(
        advanced_module,
        "load_credential_artifact",
        lambda storage_id, *, session_id=None: (
            {"storedCredential": {"id": storage_id}} if session_id == "session-id" else None
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/advanced/credential-artifacts/cred-1")

    assert response.status_code == 200
    assert response.get_json() == {
        "storageId": "cred-1",
        "artifact": {"storedCredential": {"id": "cred-1"}},
    }


def test_get_credential_artifact_route_returns_404_when_missing(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(
        advanced_module,
        "load_credential_artifact",
        lambda *_args, **_kwargs: None,
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.get("/api/advanced/credential-artifacts/missing")

    assert response.status_code == 404
    assert response.get_json() == {"error": "Credential artifact not found."}


def test_put_credential_artifact_route_requires_object_payload(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    with config_module.app.test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/cred-1",
            json={"artifact": "not-an-object"},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Artifact payload must be an object."}


def test_put_credential_artifact_route_defaults_merge_true(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)

    captured = {}

    def _store(storage_id, payload, *, merge=False, session_id=None):
        captured["storage_id"] = storage_id
        captured["payload"] = payload
        captured["merge"] = merge
        captured["session_id"] = session_id
        return True

    monkeypatch.setattr(advanced_module, "store_credential_artifact", _store, raising=False)

    with config_module.app.test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/cred-1",
            json={"artifact": {"registrationDetailSnapshot": {"html": "<p>x</p>"}}},
        )

    assert response.status_code == 200
    assert response.get_json() == {"status": "OK"}
    assert captured == {
        "storage_id": "cred-1",
        "payload": {"registrationDetailSnapshot": {"html": "<p>x</p>"}},
        "merge": True,
        "session_id": "session-id",
    }


def test_put_credential_artifact_route_supports_payload_alias_and_merge_override(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)

    captured = {}

    def _store(storage_id, payload, *, merge=False, session_id=None):
        captured["storage_id"] = storage_id
        captured["payload"] = payload
        captured["merge"] = merge
        captured["session_id"] = session_id
        return True

    monkeypatch.setattr(advanced_module, "store_credential_artifact", _store, raising=False)

    with config_module.app.test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/cred-2",
            json={"payload": {"storedCredential": {"id": "cred-2"}}, "merge": False},
        )

    assert response.status_code == 200
    assert response.get_json() == {"status": "OK"}
    assert captured == {
        "storage_id": "cred-2",
        "payload": {"storedCredential": {"id": "cred-2"}},
        "merge": False,
        "session_id": "session-id",
    }


def test_put_credential_artifact_route_returns_400_when_store_fails(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(
        advanced_module,
        "store_credential_artifact",
        lambda *_args, **_kwargs: False,
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/cred-3",
            json={"artifact": {"x": 1}},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Unable to store artifact."}


def test_put_snapshot_route_rejects_non_object_snapshot(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    with config_module.app.test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/cred-4/snapshot",
            json={"snapshot": "not-an-object"},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Snapshot must be an object."}


def test_put_snapshot_route_stores_snapshot_using_merge(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)

    captured = {}

    def _store(storage_id, payload, *, merge=False, session_id=None):
        captured["storage_id"] = storage_id
        captured["payload"] = payload
        captured["merge"] = merge
        captured["session_id"] = session_id
        return True

    monkeypatch.setattr(advanced_module, "store_credential_artifact", _store, raising=False)

    snapshot = {"html": "<section>snapshot</section>"}

    with config_module.app.test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/cred-5/snapshot",
            json={"snapshot": snapshot},
        )

    assert response.status_code == 200
    assert response.get_json() == {"status": "OK"}
    assert captured == {
        "storage_id": "cred-5",
        "payload": {"registrationDetailSnapshot": snapshot},
        "merge": True,
        "session_id": "session-id",
    }


@pytest.mark.parametrize(
    "delete_status,expected_http_status,expected_payload",
    [
        ("deleted", 200, {"status": "deleted"}),
        ("absent", 200, {"status": "absent"}),
        (
            "failed",
            500,
            {
                "status": "failed",
                "error": "Unable to delete credential artifact.",
            },
        ),
    ],
)
def test_delete_credential_artifact_route_reports_status(
    monkeypatch,
    delete_status,
    expected_http_status,
    expected_payload,
):
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    config_module = pytest.importorskip("server.app.config")

    monkeypatch.setattr(advanced_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(
        advanced_module,
        "delete_credential_artifact_with_status",
        lambda storage_id, *, session_id=None: delete_status,
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.delete("/api/advanced/credential-artifacts/cred-6")

    assert response.status_code == expected_http_status
    assert response.get_json() == expected_payload
