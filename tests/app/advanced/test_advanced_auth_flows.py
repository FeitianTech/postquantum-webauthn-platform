import base64

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_advanced_register_begin_falls_back_from_unavailable_pqc(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None
            self.attestation = None

        def register_begin(self, *_args, **_kwargs):
            params = [
                {
                    "type": getattr(param.type, "value", "public-key"),
                    "alg": param.alg,
                }
                for param in self.allowed_algorithms
            ]
            return {"publicKey": {"challenge": "AQID", "pubKeyCredParams": params}}, {"challenge": "adv-state"}

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(
        advanced_module,
        "detect_available_pqc_algorithms",
        lambda: ({-49}, "limited pqc support"),
        raising=False,
    )

    request_payload = {
        "publicKey": {
            "rp": {"id": "example.com", "name": "Example"},
            "user": {"id": "010203", "name": "user@example.com", "displayName": "User"},
            "challenge": "010203",
            "pubKeyCredParams": [{"type": "public-key", "alg": -50}],
        }
    }

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/begin", json=request_payload)

    assert response.status_code == 200
    payload = response.get_json()
    assert any("falling back to classical algorithms" in warning for warning in payload.get("warnings", []))
    response_algs = [entry["alg"] for entry in payload["publicKey"]["pubKeyCredParams"]]
    assert response_algs == [-7, -8, -257]


def test_advanced_register_complete_rejects_attachment_mismatch():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    payload = {
        "publicKey": {
            "challenge": "AQID",
            "hints": ["client-device"],
            "user": {"name": "user@example.com", "displayName": "User"},
        },
        "__credential_response": {
            "authenticatorAttachment": "cross-platform",
            "response": {},
        },
    }

    with config_module.app.test_client() as client:
        response = client.post("/api/advanced/register/complete", json=payload)

    assert response.status_code == 400
    assert "Authenticator attachment is not permitted by the selected hints" in response.get_json()["error"]


def test_advanced_authenticate_complete_rejects_non_resident_in_resident_mode(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-resident-required"
    encoded_id = _b64url(credential_id)

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [
                {
                    "id": credential_id,
                    "data": object(),
                    "attachment": None,
                    "algorithm": -7,
                    "resident": False,
                }
            ],
            [],
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {"challenge": "AQID"},
                "__storedCredentials": [{}],
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

    assert response.status_code == 400
    payload = response.get_json()
    assert "not discoverable" in payload["error"]
    assert payload["failedCredentialId"] == encoded_id


def test_advanced_authenticate_complete_missing_state_returns_400(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-missing-state"
    encoded_id = _b64url(credential_id)

    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [
                {
                    "id": credential_id,
                    "data": object(),
                    "attachment": None,
                    "algorithm": -7,
                    "resident": True,
                }
            ],
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
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__storedCredentials": [{}],
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

        assert response.status_code == 400
        assert "Authentication state not found or has expired" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "advanced_auth_rp" not in session_state


def test_advanced_authenticate_complete_custom_algorithm_bypass(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-custom-alg"
    encoded_id = _b64url(credential_id)
    custom_alg = -99999

    class _FailingServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            raise ValueError("Invalid signature.")

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FailingServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _credentials: [], raising=False)
    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [
                {
                    "id": credential_id,
                    "data": object(),
                    "attachment": None,
                    "algorithm": custom_alg,
                    "resident": True,
                }
            ],
            [],
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [
                        {"type": "public-key", "id": encoded_id, "alg": custom_alg}
                    ],
                },
                "__storedCredentials": [{}],
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "OK"
    assert payload["authenticatedCredentialId"] == encoded_id
    assert payload["customAlgorithmBypass"] is True
    assert payload["algorithm"] == custom_alg


def test_advanced_authenticate_complete_custom_algorithm_bypass_requires_requested_algorithm_match(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-custom-alg-mismatch"
    encoded_id = _b64url(credential_id)
    stored_custom_alg = -99999
    requested_alg = -99998

    class _FailingServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            raise ValueError("Invalid signature.")

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FailingServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _credentials: [], raising=False)
    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [
                {
                    "id": credential_id,
                    "data": object(),
                    "attachment": None,
                    "algorithm": stored_custom_alg,
                    "resident": True,
                }
            ],
            [],
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [
                        {"type": "public-key", "id": encoded_id, "alg": requested_alg}
                    ],
                },
                "__storedCredentials": [{}],
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "Invalid signature."
    assert payload["failedCredentialId"] == encoded_id


def test_advanced_authenticate_complete_custom_algorithm_bypass_rejects_non_signature_errors(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-custom-alg-non-signature"
    encoded_id = _b64url(credential_id)
    custom_alg = -99999

    class _FailingServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            raise ValueError("backend timeout")

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FailingServer(), raising=False)
    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _credentials: [], raising=False)
    monkeypatch.setattr(
        advanced_module,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [
                {
                    "id": credential_id,
                    "data": object(),
                    "attachment": None,
                    "algorithm": custom_alg,
                    "resident": True,
                }
            ],
            [],
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [
                        {"type": "public-key", "id": encoded_id, "alg": custom_alg}
                    ],
                },
                "__storedCredentials": [{}],
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "backend timeout"
    assert payload["failedCredentialId"] == encoded_id
