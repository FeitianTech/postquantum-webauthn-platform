import pytest


def _minimal_register_complete_payload(*, include_public_key: bool = True):
    payload = {
        "__credential_response": {
            "response": {},
        },
    }
    if include_public_key:
        payload["publicKey"] = {
            "challenge": "AQID",
            "rp": {"id": "example.com", "name": "Example RP"},
            "user": {"name": "user@example.com", "displayName": "User"},
        }
    return payload


def test_advanced_register_complete_prefers_session_state_over_request_state(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}

    class _FailingServer:
        def register_complete(self, state, _response):
            captured["state"] = state
            raise ValueError("register failure")

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FailingServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)

    session_state = {"challenge": "session-state"}
    request_state = {"challenge": "request-state"}

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_store:
            session_store["advanced_state"] = session_state
            session_store["advanced_rp"] = {"id": "example.com", "name": "Example RP"}

        payload = _minimal_register_complete_payload()
        payload["__session_state"] = request_state

        response = client.post("/api/advanced/register/complete", json=payload)

        assert response.status_code == 400
        assert response.get_json() == {"error": "register failure"}
        assert captured["state"] == session_state

        with client.session_transaction() as session_store:
            assert "advanced_state" not in session_store
            assert "advanced_rp" not in session_store


def test_advanced_register_complete_uses_request_state_fallback_when_session_missing(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}

    class _FailingServer:
        def register_complete(self, state, _response):
            captured["state"] = state
            raise ValueError("register fallback failure")

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FailingServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)

    fallback_state = {"challenge": "request-fallback-state"}

    with config_module.app.test_client() as client:
        payload = _minimal_register_complete_payload()
        payload["__session_state"] = fallback_state

        response = client.post("/api/advanced/register/complete", json=payload)

    assert response.status_code == 400
    assert response.get_json() == {"error": "register fallback failure"}
    assert captured["state"] == fallback_state


def test_advanced_register_complete_invalid_request_state_fallback_returns_400(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_store:
            session_store["advanced_rp"] = {"id": "example.com", "name": "Example RP"}

        payload = _minimal_register_complete_payload()
        payload["__session_state"] = "invalid"

        response = client.post("/api/advanced/register/complete", json=payload)

        assert response.status_code == 400
        assert "Registration state not found or has expired" in response.get_json()["error"]

        with client.session_transaction() as session_store:
            # advanced_rp remains untouched because state validation exits before RP resolution.
            assert session_store.get("advanced_rp") == {"id": "example.com", "name": "Example RP"}


def test_advanced_register_complete_requires_attachment_when_hints_resolve_to_attachment():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        payload = _minimal_register_complete_payload()
        payload["publicKey"]["hints"] = ["security-key"]

        response = client.post("/api/advanced/register/complete", json=payload)

    assert response.status_code == 400
    assert "Authenticator attachment could not be determined" in response.get_json()["error"]
