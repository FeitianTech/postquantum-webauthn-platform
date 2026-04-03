import base64

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _sample_public_key_bytes() -> bytes:
    from fido2 import cbor

    return cbor.encode(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: b"\x01" * 32,
            -3: b"\x02" * 32,
        }
    )


def _stored_credential_entry(credential_id: bytes) -> dict:
    return {
        "credentialId": _b64url(credential_id),
        "publicKey": _b64url(_sample_public_key_bytes()),
        "aaguid": _b64url(bytes.fromhex("00112233445566778899aabbccddeeff")),
        "signCount": 3,
        "resident": True,
        "authenticatorAttachment": "platform",
        "algorithm": -7,
    }


class _AuthResult:
    def __init__(self, public_key=None):
        self.public_key = public_key or {3: -7}


def test_simple_register_begin_accepts_existing_credentials_alias(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    captured = {}

    class _FakeServer:
        def register_begin(self, _user, credentials, **_kwargs):
            captured["credential_count"] = len(credentials)
            return {
                "publicKey": {
                    "challenge": "AQID",
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                }
            }, {"challenge": "simple-register-state"}

    monkeypatch.setattr(simple_module, "determine_rp_id", lambda: "example.com", raising=False)
    monkeypatch.setattr(simple_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/register/begin?email=user@example.com",
            json={"existingCredentials": [_stored_credential_entry(b"simple-register-alias")]},
        )

        assert response.status_code == 200
        payload = response.get_json()
        assert payload["__session_state"] == {"challenge": "simple-register-state"}
        assert captured["credential_count"] == 1

        with client.session_transaction() as session_state:
            assert len(session_state["simple_credentials"]) == 1


def test_simple_authenticate_begin_accepts_stored_credentials_alias(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    simple_module = pytest.importorskip("server.app.routes.simple")
    pytest.importorskip("server.app.app")

    captured = {}

    class _FakeServer:
        def authenticate_begin(self, credentials, **_kwargs):
            captured["credential_count"] = len(credentials)
            return {"publicKey": {"challenge": "AQID"}}, {"challenge": "simple-auth-state"}

    monkeypatch.setattr(simple_module, "determine_rp_id", lambda: "example.com", raising=False)
    monkeypatch.setattr(simple_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/authenticate/begin?email=user@example.com",
            json={"storedCredentials": [_stored_credential_entry(b"simple-auth-alias")]},
        )

        assert response.status_code == 200
        payload = response.get_json()
        assert payload["__session_state"] == {"challenge": "simple-auth-state"}
        assert captured["credential_count"] == 1

        with client.session_transaction() as session_state:
            assert len(session_state["simple_credentials"]) == 1


def test_advanced_register_begin_accepts_base64url_wrapped_user_id_and_challenge(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}

    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None
            self.attestation = None

        def register_begin(self, user_entity, *_args, **kwargs):
            captured["user_id"] = bytes(getattr(user_entity, "id"))
            captured["challenge"] = kwargs.get("challenge")
            return {"publicKey": {"challenge": "AQID"}}, {"challenge": "advanced-register-state"}

    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)

    user_id = b"frontend-user-id"
    challenge = b"frontend-register-challenge"

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/register/begin",
            json={
                "publicKey": {
                    "rp": {"id": "example.com", "name": "Example"},
                    "user": {
                        "id": {"$base64url": _b64url(user_id)},
                        "name": "user@example.com",
                        "displayName": "User",
                    },
                    "challenge": {"$base64url": _b64url(challenge)},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                }
            },
        )

    assert response.status_code == 200
    assert captured["user_id"] == user_id
    assert captured["challenge"] == challenge


def test_advanced_register_begin_rejects_invalid_binary_wrapper_in_user_id():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/register/begin",
            json={
                "publicKey": {
                    "rp": {"id": "example.com", "name": "Example"},
                    "user": {
                        "id": {"$hex": "zz"},
                        "name": "user@example.com",
                        "displayName": "User",
                    },
                    "challenge": "00112233445566778899aabbccddeeff",
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                }
            },
        )

    assert response.status_code == 400
    assert "Invalid user ID format" in response.get_json()["error"]


def test_advanced_authenticate_begin_accepts_storedcredentials_without_dunder(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}

    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None

        def authenticate_begin(self, credentials, **kwargs):
            captured["credential_count"] = 0 if credentials is None else len(credentials)
            captured["challenge"] = kwargs.get("challenge")
            return {
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": "placeholder"}],
                }
            }, {"challenge": "advanced-auth-state"}

    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)
    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)

    credential_id = b"frontend-adv-auth"
    challenge = b"frontend-auth-challenge"

    wrapped_entry = {
        "credentialId": {"$base64url": _b64url(credential_id)},
        "publicKey": {"$base64url": _b64url(_sample_public_key_bytes())},
        "aaguid": {"$hex": "00112233445566778899aabbccddeeff"},
        "resident": True,
        "authenticatorAttachment": "platform",
        "algorithm": -7,
    }

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {"challenge": {"$base64url": _b64url(challenge)}},
                "storedCredentials": [wrapped_entry],
            },
        )

        assert response.status_code == 200
        payload = response.get_json()
        assert payload["__session_state"] == {"challenge": "advanced-auth-state"}
        assert "allowCredentials" not in payload["publicKey"]
        assert captured["credential_count"] == 1
        assert captured["challenge"] == challenge


def test_advanced_authenticate_begin_accepts_credentials_fallback_field(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    captured = {}

    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None

        def authenticate_begin(self, credentials, **_kwargs):
            captured["credential_count"] = 0 if credentials is None else len(credentials)
            return {"publicKey": {"challenge": "AQID"}}, {"challenge": "advanced-auth-state"}

    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)
    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/begin",
            json={
                "publicKey": {"challenge": "010203"},
                "credentials": [_stored_credential_entry(b"advanced-auth-credentials-field")],
            },
        )

    assert response.status_code == 200
    assert captured["credential_count"] == 1


def test_advanced_authenticate_complete_accepts_storedcredentials_without_dunder(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"adv-complete-storedCredentials"
    encoded_credential_id = _b64url(credential_id)

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            return _AuthResult({3: -7})

    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)
    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _credentials: [], raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_credential_id}],
                },
                "storedCredentials": [_stored_credential_entry(credential_id)],
                "__assertion_response": {"rawId": encoded_credential_id, "response": {}},
            },
        )

    assert response.status_code == 200
    assert response.get_json()["authenticatedCredentialId"] == encoded_credential_id


def test_advanced_authenticate_complete_accepts_credentials_fallback_field(monkeypatch):
    config_module = pytest.importorskip("server.app.config")
    advanced_module = pytest.importorskip("server.app.routes.advanced")
    pytest.importorskip("server.app.app")

    credential_id = b"adv-complete-credentials-field"
    encoded_credential_id = _b64url(credential_id)

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            return _AuthResult({3: -7})

    monkeypatch.setattr(advanced_module, "determine_rp_id", lambda value=None: value or "example.com", raising=False)
    monkeypatch.setattr(advanced_module, "create_fido_server", lambda **_kwargs: _FakeServer(), raising=False)
    monkeypatch.setattr(advanced_module, "_derive_algorithms_from_credentials", lambda _credentials: [], raising=False)

    with config_module.app.test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_credential_id}],
                },
                "credentials": [_stored_credential_entry(credential_id)],
                "__assertion_response": {"rawId": encoded_credential_id, "response": {}},
            },
        )

    assert response.status_code == 200
    assert response.get_json()["authenticatedCredentialId"] == encoded_credential_id
