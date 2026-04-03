import base64

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class _AuthResult:
    def __init__(self, public_key=None):
        self.public_key = public_key or {3: -7}


def test_advanced_authenticate_complete_uses_request_state_fallback(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-fallback-state"
    encoded_id = _b64url(credential_id)
    captured = {}

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, state, *_args, **_kwargs):
            captured["state"] = state
            return _AuthResult()

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _credentials: [], raising=False)
    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}],
            [],
        ),
        raising=False,
    )

    fallback_state = {"challenge": "fallback-state"}

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "__session_state": fallback_state,
                "__storedCredentials": [{}],
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__assertion_response": {
                    "rawId": encoded_id,
                    "response": {},
                },
            },
        )

        assert response.status_code == 200
        assert captured["state"] == fallback_state

        with client.session_transaction() as session_state:
            assert "advanced_auth_rp" not in session_state


def test_advanced_authenticate_complete_uses_advanced_rp_when_auth_rp_missing(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-rp-fallback"
    encoded_id = _b64url(credential_id)
    captured = {}

    class _FakeServer:
        allowed_algorithms = []

        def __init__(self, *, rp_id):
            captured["server_rp_id"] = rp_id

        def authenticate_complete(self, *_args, **_kwargs):
            return _AuthResult()

    def _determine_rp_id(value=None):
        captured["determine_rp_id_arg"] = value
        return value or "default.example"

    monkeypatch.setattr(advanced_module, "determine_rp_id", _determine_rp_id, raising=False)
    monkeypatch.setattr(
        advanced_module,
        "create_fido_server",
        lambda **kwargs: _FakeServer(rp_id=kwargs.get("rp_id")),
        raising=False,
    )
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _credentials: [], raising=False)
    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}],
            [],
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_rp"] = {"id": "fallback.example", "name": "Fallback"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "__storedCredentials": [{}],
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__assertion_response": {
                    "rawId": encoded_id,
                    "response": {},
                },
            },
        )

        assert response.status_code == 200
        assert captured["determine_rp_id_arg"] == "fallback.example"
        assert captured["server_rp_id"] == "fallback.example"


def test_advanced_authenticate_complete_invalid_request_state_fallback_returns_400(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-invalid-fallback"
    encoded_id = _b64url(credential_id)

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}],
            [],
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "__session_state": "invalid",
                "__storedCredentials": [{}],
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__assertion_response": {
                    "rawId": encoded_id,
                    "response": {},
                },
            },
        )

        assert response.status_code == 400
        assert "Authentication state not found or has expired" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "advanced_auth_rp" not in session_state


def test_advanced_authenticate_complete_reports_cookie_restore_failure(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: ([], []),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_credentials_meta"] = {
                "count": 50,
                "resident_count": 10,
            }

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {"challenge": "AQID"},
                "__storedCredentials": [{"record": 1}],
                "__assertion_response": {"response": {}},
            },
        )

        assert response.status_code == 400
        payload = response.get_json()
        assert "session cookie exceeded" in payload["error"]

        with client.session_transaction() as session_state:
            assert "advanced_auth_credentials_meta" not in session_state


def test_advanced_authenticate_complete_requires_attachment_when_session_scopes_allowed_attachments():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_authenticate_allowed_attachments"] = ["platform"]

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {"challenge": "AQID"},
                "__assertion_response": {"response": {}},
            },
        )

        assert response.status_code == 400
        assert "Authenticator attachment could not be determined" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "advanced_authenticate_allowed_attachments" not in session_state


def test_advanced_authenticate_complete_rejects_attachment_not_allowed_by_session_scope():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_authenticate_allowed_attachments"] = ["platform"]

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {"challenge": "AQID"},
                "__assertion_response": {
                    "authenticatorAttachment": "cross-platform",
                    "response": {},
                },
            },
        )

        assert response.status_code == 400
        assert "Authenticator attachment is not permitted by the selected hints" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "advanced_authenticate_allowed_attachments" not in session_state
