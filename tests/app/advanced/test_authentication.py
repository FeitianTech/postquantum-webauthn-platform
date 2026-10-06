"""Tests for the advanced authenticate complete route."""

from __future__ import annotations

from types import SimpleNamespace

from server.app.config import relying_party
from server.app.routes.advanced import algorithms as advanced_algorithms
from server.app.routes.advanced import parsing as advanced_parsing
from server.app.webauthn import assertion_hash
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import Authenticator, assertion_payload, b64u

from .assertion_ceremony import CHALLENGE, begin, complete


def _complete(client, body):
    return client.post("/api/advanced/authenticate/complete", json=body)


def test_a_complete_without_public_key_options_is_refused():
    response = _complete(entry_app().test_client(), {"__assertion_response": {"response": {}}})

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request: Missing publicKey in JSON editor content"}


def test_a_verified_assertion_reports_the_credentials_algorithm_and_counter():
    authenticator = Authenticator()
    credentials = [authenticator.stored_credential_entry()]
    client = entry_app().test_client()
    begin(client, credentials)

    response = complete(client, credentials, assertion_payload(authenticator, challenge=CHALLENGE, counter=7))

    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert (body["status"], body["algorithm"], body["signCount"]) == ("OK", -7, 7)
    assert body["authenticatedCredentialId"] == b64u(authenticator.credential_id)


def test_a_complete_that_sends_no_credentials_finds_none_whatever_its_begin_was_sent():
    authenticator = Authenticator()
    credentials = [authenticator.stored_credential_entry()]
    client = entry_app().test_client()
    begin(client, credentials)

    response = complete(client, None, assertion_payload(authenticator, challenge=CHALLENGE, counter=7))

    assert response.status_code == 404
    assert response.get_json()["error"] == "No credentials found"


def test_a_complete_whose_sent_credentials_cannot_be_read_says_so():
    authenticator = Authenticator()
    client = entry_app().test_client()
    begin(client, [authenticator.stored_credential_entry()])

    response = complete(client, ["unparseable"], assertion_payload(authenticator, challenge=CHALLENGE, counter=7))

    assert response.status_code == 400
    assert response.get_json()["error"] == (
        "None of the saved credentials sent with this authentication could be read. "
        "Please register a credential and try again."
    )


def test_begin_gives_the_browser_the_requests_hints():
    authenticator = Authenticator(credential_id=b"\x04" * 32)

    entry = {**authenticator.stored_credential_entry(), "authenticatorAttachment": "cross-platform"}

    response = begin(entry_app().test_client(), [entry], hints=["security-key"])

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["publicKey"]["hints"] == ["security-key"]


def test_begin_names_no_hints_when_the_request_has_none():
    authenticator = Authenticator(credential_id=b"\x04" * 32)

    response = begin(entry_app().test_client(), [authenticator.stored_credential_entry()])

    assert response.status_code == 200, response.get_json()
    assert "hints" not in response.get_json()["publicKey"]


def test_begin_refuses_an_extension_value_it_cannot_read():
    authenticator = Authenticator(credential_id=b"\x04" * 32)

    response = begin(
        entry_app().test_client(),
        [authenticator.stored_credential_entry()],
        extensions={"largeBlob": {"write": "not hex"}},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid extension value: input is not hexadecimal"}


def test_begin_refuses_a_public_key_that_is_no_object():
    response = entry_app().test_client().post("/api/advanced/authenticate/begin", json={"publicKey": ["challenge"]})

    assert response.status_code == 400
    assert response.get_json() == {"error": "publicKey must be an object."}


def test_advanced_authenticate_complete_without_session_state_returns_400(monkeypatch):
    credential_id = b"advanced-invalid-fallback"
    encoded_id = b64u(credential_id)

    monkeypatch.setattr(
        advanced_parsing,
        "_parse_client_supplied_credentials",
        lambda _raw: [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}]
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
        lambda _raw: [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}]
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
        lambda _raw: [{"id": credential_id, "data": object(), "attachment": None, "algorithm": -7, "resident": True}]
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
