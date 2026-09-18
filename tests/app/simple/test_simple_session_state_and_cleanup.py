import base64
import time

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class _MatchedCredential:
    def __init__(self, credential_id: bytes):
        self.credential_id = credential_id


def test_register_complete_rejects_non_mapping_request_state_fallback(monkeypatch, attestation_module):
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(
        attestation_module,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["register_rp_id"] = "example.com"

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json={
                "__session_state": "not-a-mapping",
                "response": {
                    "attestationObject": _b64url(b"attestation"),
                    "clientDataJSON": _b64url(b"client"),
                },
            },
        )

    assert response.status_code == 400
    assert "Registration state not found or has expired" in response.get_json()["error"]


def test_authenticate_complete_invalid_request_state_fallback_returns_400(monkeypatch, simple_parsing):
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    monkeypatch.setattr(
        simple_parsing,
        "_parse_client_credentials_impl",
        lambda _raw: ([object()], [{"credentialId": "cred-1"}])
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["simple_credentials"] = [{"credentialId": "cred-1"}]
            session_state["authenticate_rp_id"] = "example.com"
            session_state["simple_credentials_email"] = "user@example.com"

        response = client.post(
            "/api/authenticate/complete?email=user@example.com",
            json={
                "rawId": "cred-1",
                "response": {},
                "__session_state": "invalid",
            },
        )

        assert response.status_code == 400
        assert "Authentication state not found or has expired" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "authenticate_rp_id" not in session_state
            assert session_state.get("simple_credentials_email") == "user@example.com"


def test_authenticate_complete_malformed_authenticator_data_is_rejected(monkeypatch, config_module, simple_parsing):
    pytest.importorskip("server.app.app")

    credential_id = b"simple-auth-no-sign-count"

    class _FakeServer:
        def authenticate_complete(self, *_args, **_kwargs):
            return _MatchedCredential(credential_id)

    monkeypatch.setattr(config_module, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(
        simple_parsing,
        "_parse_client_credentials_impl",
        lambda _raw: ([object()], [{"credentialId": _b64url(credential_id)}])
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["simple_credentials"] = [{"credentialId": _b64url(credential_id)}]
            session_state["state"] = {"challenge": "auth-state", "issued_at": time.time()}
            session_state["authenticate_rp_id"] = "example.com"
            session_state["simple_credentials_email"] = "user@example.com"

        response = client.post(
            "/api/authenticate/complete?email=user@example.com",
            json={
                "rawId": _b64url(credential_id),
                "response": {"authenticatorData": "not-valid-base64url"},
            },
        )

        # An unreadable counter cannot pass the signCount check.
        assert response.status_code == 400
        payload = response.get_json()
        assert payload.get("status") != "OK"
        assert "signature counter could not be read" in payload["error"]
        assert "signCount" not in payload

        with client.session_transaction() as session_state:
            assert "simple_credentials_email" not in session_state
            assert "authenticate_rp_id" not in session_state
