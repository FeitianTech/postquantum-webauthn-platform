
from types import SimpleNamespace

from server.app.config import relying_party
from server.app.routes.advanced import algorithms as advanced_algorithms
from server.app.routes.advanced import parsing as advanced_parsing
from server.app.webauthn import assertion_hash
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import b64u


def test_advanced_authenticate_complete_without_session_state_returns_400(monkeypatch):
    credential_id = b"advanced-invalid-fallback"
    encoded_id = b64u(credential_id)

    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}],
            [],
        )
    )

    with entry_app().test_client() as client:
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


def test_advanced_authenticate_complete_reports_unreadable_sent_credentials(monkeypatch):
    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: ([], [])
    )

    with entry_app().test_client() as client:
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
        assert "None of the saved credentials sent with this authentication could be read" in payload["error"]

        with client.session_transaction() as session_state:
            assert "advanced_auth_credentials_meta" not in session_state


def test_advanced_authenticate_complete_requires_attachment_when_session_scopes_allowed_attachments():
    with entry_app().test_client() as client:
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
    with entry_app().test_client() as client:
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


def test_advanced_authenticate_complete_forwards_hash_algorithm_override(monkeypatch):
    credential_id = b"advanced-hash-forward"
    encoded_id = b64u(credential_id)
    captured = {}

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, _state, _credentials, response):
            captured["response"] = response
            return SimpleNamespace(public_key={3: -7})

    def _hashed_with(response, algorithm):
        captured["hash_algorithm"] = algorithm
        return response


    monkeypatch.setattr(assertion_hash, "response_hashed_with", _hashed_with)

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _credentials: [])
    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}],
            [],
        )
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "__hash_algorithm": "SHA-512",
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__storedCredentials": [{}],
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

    assert response.status_code == 200
    assert captured["hash_algorithm"] == "SHA-512"


def test_advanced_authenticate_complete_defaults_hash_algorithm_when_override_invalid(monkeypatch):
    credential_id = b"advanced-hash-default"
    encoded_id = b64u(credential_id)
    captured = {}

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, _state, _credentials, response):
            captured["response"] = response
            return SimpleNamespace(public_key={3: -7})

    def _hashed_with(response, algorithm):
        captured["hash_algorithm"] = algorithm
        return response


    monkeypatch.setattr(assertion_hash, "response_hashed_with", _hashed_with)

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _credentials: [])
    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}],
            [],
        )
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["advanced_auth_state"] = {"challenge": "state"}
            session_state["advanced_auth_rp"] = {"id": "example.com", "name": "Example"}

        response = client.post(
            "/api/advanced/authenticate/complete",
            json={
                "__hash_algorithm": {"invalid": True},
                "publicKey": {
                    "challenge": "AQID",
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__storedCredentials": [{}],
                "__assertion_response": {"rawId": encoded_id, "response": {}},
            },
        )

    assert response.status_code == 200
    assert captured["hash_algorithm"] == "SHA-256"


def test_advanced_authenticate_complete_omits_sign_count_for_malformed_authenticator_data(monkeypatch):
    credential_id = b"advanced-malformed-authdata"
    encoded_id = b64u(credential_id)

    class _FakeServer:
        allowed_algorithms = []

        def authenticate_complete(self, *_args, **_kwargs):
            return SimpleNamespace(public_key={3: -7})

    monkeypatch.setattr(relying_party, "create_fido_server", lambda **_kwargs: _FakeServer())
    monkeypatch.setattr(relying_party, "determine_rp_id", lambda value=None: value or "example.com")
    monkeypatch.setattr(advanced_algorithms, "_derive_algorithms_from_credentials", lambda _credentials: [])
    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: (
            [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}],
            [],
        )
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
                    "allowCredentials": [{"type": "public-key", "id": encoded_id}],
                },
                "__storedCredentials": [{}],
                "__assertion_response": {
                    "rawId": encoded_id,
                    "response": {"authenticatorData": "%%not-valid%%"},
                },
            },
        )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "OK"
    assert payload["authenticatedCredentialId"] == encoded_id
    assert "signCount" not in payload
