
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
