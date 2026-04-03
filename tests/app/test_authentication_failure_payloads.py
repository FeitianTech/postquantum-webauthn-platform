import base64

import pytest


def _encode_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_simple_authentication_failure_returns_failed_credential_id(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    credential_id = b"simple-credential-id"
    encoded_id = _encode_base64url(credential_id)

    class _FailingServer:
        def authenticate_complete(self, *_args, **_kwargs):
            raise ValueError("Invalid signature.")

    monkeypatch.setattr(simple_module, "create_fido_server", lambda **_kwargs: _FailingServer(), raising=False)
    monkeypatch.setattr(simple_module, "_parse_client_credentials", lambda _raw: ([object()], []), raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session:
            session["simple_credentials"] = [{"credentialIdBase64Url": encoded_id}]
            session["state"] = {"challenge": "test"}
            session["authenticate_rp_id"] = "example.com"

        response = client.post(
            f"/api/authenticate/complete?email={encoded_id}@example.com",
            json={
                "rawId": encoded_id,
                "response": {},
            },
        )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Invalid signature.",
        "failedCredentialId": encoded_id,
    }


def test_advanced_authentication_failure_returns_failed_credential_id(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"advanced-credential-id"
    encoded_id = _encode_base64url(credential_id)

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
            [{"id": credential_id, "data": {"public_key": {3: -7}}, "resident": True}],
            [],
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        with client.session_transaction() as session:
            session["advanced_auth_state"] = {"challenge": "test"}
            session["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "__assertion_response": {
                    "rawId": encoded_id,
                    "response": {},
                },
                "__storedCredentials": [{}],
                "publicKey": {
                    "challenge": encoded_id,
                    "allowCredentials": [
                        {
                            "type": "public-key",
                            "id": encoded_id,
                        }
                    ],
                },
            },
        )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Invalid signature.",
        "failedCredentialId": encoded_id,
    }
