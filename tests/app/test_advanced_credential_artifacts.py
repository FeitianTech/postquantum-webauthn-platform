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
