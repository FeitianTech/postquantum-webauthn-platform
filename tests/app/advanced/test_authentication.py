"""Tests for the advanced authenticate complete route."""
from __future__ import annotations

from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import Authenticator, assertion_payload, b64u

from .assertion_ceremony import CHALLENGE, begin, complete


def _complete(client, body):
    return client.post("/api/advanced/authenticate/complete", json=body)


def test_a_complete_without_an_assertion_response_is_refused():
    response = _complete(entry_app().test_client(), {"publicKey": {"challenge": "AQID"}})

    assert response.status_code == 400
    assert response.get_json() == {"error": "Assertion response is required"}


def test_a_complete_without_public_key_options_is_refused():
    response = _complete(entry_app().test_client(), {"__assertion_response": {"response": {}}})

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request: Missing publicKey in JSON editor content"}


def test_a_complete_with_no_saved_credential_anywhere_finds_none():
    client = entry_app().test_client()
    with client.session_transaction() as session:
        session["advanced_auth_credentials_meta"] = {"count": 2, "resident_count": 1}

    response = _complete(client, {"publicKey": {"challenge": "AQID"}, "__assertion_response": {"response": {}}})

    assert response.status_code == 404
    assert response.get_json() == {"error": "No credentials found"}
    with client.session_transaction() as session:
        assert "advanced_auth_credentials_meta" not in session


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
