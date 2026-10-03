
from server.app.config import relying_party
from server.app.routes.advanced import algorithms as advanced_algorithms
from server.app.routes.advanced import parsing as advanced_parsing
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import b64u


def test_advanced_register_complete_rejects_attachment_mismatch():
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

    with entry_app().test_client() as client:
        response = client.post("/api/advanced/register/complete", json=payload)

    assert response.status_code == 400
    assert "Authenticator attachment is not permitted by the selected hints" in response.get_json()["error"]


def test_advanced_authenticate_complete_rejects_non_resident_in_resident_mode(monkeypatch):
    credential_id = b"advanced-resident-required"
    encoded_id = b64u(credential_id)

    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [
            {
                "id": credential_id,
                "data": object(),
                "attachment": None,
                "algorithm": -7,
                "resident": False,
            }
        ]
    )

    with entry_app().test_client() as client:
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
    credential_id = b"advanced-missing-state"
    encoded_id = b64u(credential_id)

    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [
            {
                "id": credential_id,
                "data": object(),
                "attachment": None,
                "algorithm": -7,
                "resident": True,
            }
        ]
    )

    with entry_app().test_client() as client:
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


def test_advanced_authenticate_complete_custom_algorithm_does_not_bypass_verification(monkeypatch):
    """A custom/unknown declared algorithm must never yield status OK."""

    credential_id = b"advanced-custom-alg"
    encoded_id = b64u(credential_id)
    custom_alg = -99999

    class _FailingServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            raise ValueError("Invalid signature.")

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FailingServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _credentials: [])
    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [
            {
                "id": credential_id,
                "data": object(),
                "attachment": None,
                "algorithm": custom_alg,
                "resident": True,
            }
        ]
    )

    with entry_app().test_client() as client:
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
    assert payload["status"] != "OK"
    assert payload["verified"] is False
    assert payload["signatureVerified"] is False
    assert payload["failedCredentialId"] == encoded_id
    # The old bypass marker must be gone entirely.
    assert "customAlgorithmBypass" not in payload


def test_advanced_authenticate_complete_custom_algorithm_bypass_requires_requested_algorithm_match(monkeypatch):
    credential_id = b"advanced-custom-alg-mismatch"
    encoded_id = b64u(credential_id)
    stored_custom_alg = -99999
    requested_alg = -99998

    class _FailingServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            raise ValueError("Invalid signature.")

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FailingServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _credentials: [])
    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [
            {
                "id": credential_id,
                "data": object(),
                "attachment": None,
                "algorithm": stored_custom_alg,
                "resident": True,
            }
        ]
    )

    with entry_app().test_client() as client:
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
    credential_id = b"advanced-custom-alg-non-signature"
    encoded_id = b64u(credential_id)
    custom_alg = -99999

    class _FailingServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            raise ValueError("backend timeout")

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FailingServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _credentials: [])
    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [
            {
                "id": credential_id,
                "data": object(),
                "attachment": None,
                "algorithm": custom_alg,
                "resident": True,
            }
        ]
    )

    with entry_app().test_client() as client:
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
