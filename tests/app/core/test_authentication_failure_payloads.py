import base64
import time

from server.app.config import relying_party
from tests.app.entry_app import entry_app


def _encode_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_simple_authentication_failure_returns_failed_credential_id(monkeypatch, config_module, simple_parsing):
    credential_id = b"simple-credential-id"
    encoded_id = _encode_base64url(credential_id)

    class _FailingServer:
        def authenticate_complete(self, *_args, **_kwargs):
            raise ValueError("Invalid signature.")

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FailingServer())
    monkeypatch.setattr(simple_parsing, "_parse_client_credentials", lambda _raw: ([object()], []))

    with entry_app().test_client() as client:
        with client.session_transaction() as session:
            session["simple_credentials"] = [{"credentialIdBase64Url": encoded_id}]
            session["state"] = {"challenge": "test", "issued_at": time.time()}
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


def test_advanced_authentication_failure_returns_failed_credential_id(monkeypatch, config_module, advanced_algorithms, advanced_parsing):
    credential_id = b"advanced-credential-id"
    encoded_id = _encode_base64url(credential_id)

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
        lambda _raw: (
            [{"id": credential_id, "data": {"public_key": {3: -7}}, "resident": True}],
            [],
        )
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session:
            session["advanced_auth_state"] = {"challenge": "test", "issued_at": time.time()}
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
    # A failed signature is now an explicit non-OK verdict, not a bare error.
    assert response.get_json() == {
        "status": "VERIFICATION_FAILED",
        "verified": False,
        "signatureVerified": False,
        "error": "Invalid signature.",
        "failedCredentialId": encoded_id,
        "challengeSource": "server-session",
        "challengeStatus": "fresh",
    }
