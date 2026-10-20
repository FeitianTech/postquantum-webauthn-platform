
from server.app.routes.simple import parsing as simple_parsing
from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    Authenticator,
    assertion_payload,
    b64u,
    begin_simple_registration,
    keep_simple_credentials,
    register_simple,
    registration_payload,
    simple_complete_body,
    unb64u,
)

EMAIL = "user@example.com"


def test_register_complete_rejects_non_mapping_request_state_fallback(monkeypatch):
    monkeypatch.setattr(
        attestation_certificates,
        "extract_attestation_details",
        lambda _response: ("none", {}, None, None, {}, None, [])
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            session_state["register_rp_id"] = "example.com"

        response = client.post(
            "/api/register/complete?email=user@example.com",
            json={
                "__session_state": "not-a-mapping",
                "response": {
                    "attestationObject": b64u(b"attestation"),
                    "clientDataJSON": b64u(b"client"),
                },
            },
        )

    assert response.status_code == 400
    assert "Registration state not found or has expired" in response.get_json()["error"]


def test_authenticate_complete_invalid_request_state_fallback_returns_400(monkeypatch):
    monkeypatch.setattr(
        simple_parsing,
        "_parse_client_credentials",
        lambda _raw: ([object()], [{"credentialId": "cred-1"}])
    )

    with entry_app().test_client() as client:
        with client.session_transaction() as session_state:
            keep_simple_credentials(session_state, [{"credentialId": "cred-1"}])
            session_state["authenticate_rp_id"] = "example.com"
            session_state["simple_credentials_email"] = "user@example.com"

        response = client.post(
            "/api/authenticate/complete?email=user@example.com",
            json=simple_complete_body(
                {"rawId": "cred-1", "response": {}, "__session_state": "invalid"}, [{"credentialId": "cred-1"}]
            ),
        )

        assert response.status_code == 400
        assert "Authentication state not found or has expired" in response.get_json()["error"]

        with client.session_transaction() as session_state:
            assert "authenticate_rp_id" not in session_state
            assert session_state.get("simple_credentials_email") == "user@example.com"


def _begin_authentication(client, entry) -> bytes:
    begin = client.post(f"/api/authenticate/begin?email={EMAIL}", json={"credentials": [entry]})
    assert begin.status_code == 200, begin.get_json()
    return unb64u(begin.get_json()["publicKey"]["challenge"])


def test_a_registration_begun_during_an_authentication_leaves_its_state_alone(credential_store):
    authenticator = Authenticator()
    client = entry_app().test_client()
    register_simple(client, authenticator)
    entry = authenticator.stored_credential_entry()

    challenge = _begin_authentication(client, entry)
    begin_simple_registration(client)
    complete = client.post(
        f"/api/authenticate/complete?email={EMAIL}",
        json=simple_complete_body(assertion_payload(authenticator, challenge=challenge, counter=1), [entry]),
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
    with client.session_transaction() as session_state:
        assert "simple_register_state" in session_state


def test_an_authentication_begun_during_a_registration_leaves_its_state_alone(credential_store):
    registered = Authenticator(credential_id=b"\x01" * 32)
    client = entry_app().test_client()
    register_simple(client, registered)

    challenge = begin_simple_registration(client)
    _begin_authentication(client, registered.stored_credential_entry())
    complete = client.post(
        f"/api/register/complete?email={EMAIL}",
        json=registration_payload(Authenticator(credential_id=b"\x02" * 32), challenge=challenge),
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
    with client.session_transaction() as session_state:
        assert "simple_authenticate_state" in session_state
