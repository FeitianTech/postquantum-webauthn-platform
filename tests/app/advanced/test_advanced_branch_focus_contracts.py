from __future__ import annotations

import base64

from server.app.config import relying_party
from tests.app.entry_app import entry_app


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _authenticator_data_b64url(counter: int) -> str:
    raw = b"\x00" * 32 + b"\x01" + int(counter).to_bytes(4, "big")
    return _b64url(raw)


def _credential_record(credential_id, *, data=None, attachment=None, resident=False, algorithm=-7):
    return {
        "id": credential_id,
        "data": object() if data is None else data,
        "attachment": attachment,
        "algorithm": algorithm,
        "resident": resident,
    }


def _serialized_record(*, resident=False):
    return {
        "credentialId": "credential",
        "publicKey": "public-key",
        "resident": resident,
    }


def _install_fake_auth_begin_server(monkeypatch, advanced_module, captured, config_module):
    class _FakeServer:
        def __init__(self):
            self.allowed_algorithms = []
            self.timeout = None

        def authenticate_begin(self, credentials, *, user_verification, challenge, extensions):
            captured["credentials"] = credentials
            captured["user_verification"] = user_verification
            captured["challenge"] = challenge
            captured["extensions"] = extensions
            captured["allowed_algorithms"] = self.allowed_algorithms
            return {
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": "placeholder"}],
                }
            }, {"challenge": "state-token"}

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(
        relying_party,
        "determine_rp_id",
        lambda value=None: value or "example.com"
    )


def test_advanced_authenticate_complete_requires_assertion_response():
    with entry_app().test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/complete",
            json={"publicKey": {"challenge": "AQID"}},
        )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Assertion response is required",
    }


def test_advanced_authenticate_complete_requires_public_key_payload():
    with entry_app().test_client() as client:
        response = client.post(
            "/api/advanced/authenticate/complete",
            json={"__assertion_response": {"response": {}}},
        )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Invalid request: Missing publicKey in JSON editor content",
    }


def test_advanced_authenticate_complete_uses_legacy_session_credentials_fallback(monkeypatch, config_module, advanced_algorithms, advanced_parsing):

    credential_id = b"legacy-credential"
    encoded_id = _b64url(credential_id)

    legacy_payload = [{"legacy": True}]

    def _parse(raw):
        if raw == legacy_payload:
            return (
                [_credential_record(credential_id, resident=True)],
                [_serialized_record(resident=True)],
            )
        return ([], [])

    class _AuthResult:
        public_key = {3: -7}

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            return _AuthResult()

    monkeypatch.setattr(advanced_parsing, "_parse_client_supplied_credentials", _parse)
    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _source: [])

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state-token"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}
            session_state["advanced_auth_credentials"] = legacy_payload

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

        assert response.status_code == 200
        assert response.get_json()["status"] == "OK"

        with client.session_transaction() as session_state:
            assert "advanced_auth_credentials" not in session_state


def test_advanced_authenticate_complete_returns_404_when_no_credentials_found_anywhere():
    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_credentials_meta"] = {"count": 2, "resident_count": 1}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "publicKey": {"challenge": "AQID"},
                "__assertion_response": {"response": {}},
            },
        )

        assert response.status_code == 404
        assert response.get_json() == {
            "error": "No credentials found",
        }

        with client.session_transaction() as session_state:
            assert "advanced_auth_credentials_meta" not in session_state
