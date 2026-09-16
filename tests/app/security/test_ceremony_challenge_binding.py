"""Fix 1 -- the ceremony challenge must come from the server, not the client.

Every ``/begin`` used to hand the server's own state (including the challenge)
back to the client as ``__session_state``, and every ``/complete`` accepted it
back whenever the Flask session was empty -- so the server ended up comparing
the client's challenge against the client's own value.

The simple flow must now bind the challenge to the server session only. The
advanced flow (a request editor) may still accept a client-supplied state, but
must always say so via ``challengeSource``.
"""
from __future__ import annotations

from .ceremony_helpers import (
    ORIGIN,
    RP_ID,
    Authenticator,
    advanced_public_key_options,
    assertion_payload,
    b64u,
    registration_payload,
    unb64u,
)


# --------------------------------------------------------------------------
# NEGATIVE -- the tech lead's PoC, adapted.
# --------------------------------------------------------------------------


def test_cold_simple_register_complete_with_self_chosen_challenge_is_rejected(
    config_module, simple_module, simple_storage
):
    """A cold /complete with no session cookie and a self-chosen challenge.

    This is the confirmed-exploitable PoC: the attacker never calls /begin, and
    picks the challenge itself. It must now be rejected outright.
    """

    authenticator = Authenticator()
    attacker_challenge = b"\xAA" * 32

    payload = registration_payload(authenticator, challenge=attacker_challenge)
    payload["__session_state"] = {
        "challenge": b64u(attacker_challenge),
        "user_verification": None,
    }

    client = config_module.app.test_client()
    # No /begin call, so no session cookie: a cold, unauthenticated request.
    response = client.post(
        "/api/register/complete?email=attacker@example.com",
        json=payload,
        headers={"Origin": ORIGIN, "Host": RP_ID},
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body.get("status") != "OK"
    assert "state" in body["error"].lower()
    # Nothing may have been persisted.
    assert simple_storage == {}


def test_cold_simple_authenticate_complete_with_self_chosen_challenge_is_rejected(
    config_module, simple_module
):
    """The same bypass against the authentication ceremony."""

    authenticator = Authenticator()
    attacker_challenge = b"\xBB" * 32

    payload = assertion_payload(authenticator, challenge=attacker_challenge)
    payload["__session_state"] = {"challenge": b64u(attacker_challenge)}

    client = config_module.app.test_client()
    with client.session_transaction() as session:
        # Credentials are known, but there is no server-issued ceremony state.
        session["simple_credentials"] = [authenticator.stored_credential_entry()]

    response = client.post(
        "/api/authenticate/complete?email=attacker@example.com",
        json=payload,
        headers={"Origin": ORIGIN, "Host": RP_ID},
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body.get("status") != "OK"
    assert "state" in body["error"].lower()


def test_simple_register_complete_ignores_request_supplied_state(
    config_module, simple_module, simple_storage
):
    """Even with a valid session, the request-supplied state must be ignored."""

    authenticator = Authenticator()
    client = config_module.app.test_client()

    begin = client.post("/api/register/begin?email=user@example.com", json={"credentials": []})
    server_challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    # Sign against a challenge of our own choosing, then try to smuggle the
    # matching state in alongside it.
    attacker_challenge = b"\xCC" * 32
    payload = registration_payload(authenticator, challenge=attacker_challenge)
    payload["__session_state"] = {"challenge": b64u(attacker_challenge)}

    response = client.post(
        "/api/register/complete?email=user@example.com",
        json=payload,
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    assert response.get_json().get("status") != "OK"
    assert simple_storage == {}
    assert attacker_challenge != server_challenge


# --------------------------------------------------------------------------
# The server state must never leave the server in the simple flow.
# --------------------------------------------------------------------------


def test_simple_register_begin_does_not_disclose_ceremony_state(config_module):
    client = config_module.app.test_client()
    response = client.post("/api/register/begin?email=user@example.com", json={"credentials": []})

    assert response.status_code == 200
    assert "__session_state" not in response.get_json()


def test_simple_authenticate_begin_does_not_disclose_ceremony_state(config_module):
    authenticator = Authenticator()
    client = config_module.app.test_client()
    response = client.post(
        "/api/authenticate/begin?email=user@example.com",
        json={"credentials": [authenticator.stored_credential_entry()]},
    )

    assert response.status_code == 200
    assert "__session_state" not in response.get_json()


# --------------------------------------------------------------------------
# POSITIVE -- the simple happy path still works, end to end, with real crypto.
# --------------------------------------------------------------------------


def test_simple_registration_and_authentication_happy_path(
    config_module, simple_module, simple_storage
):
    authenticator = Authenticator()
    client = config_module.app.test_client()

    begin = client.post("/api/register/begin?email=user@example.com", json={"credentials": []})
    assert begin.status_code == 200
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    complete = client.post(
        "/api/register/complete?email=user@example.com",
        json=registration_payload(authenticator, challenge=challenge),
        headers={"Origin": ORIGIN},
    )
    assert complete.status_code == 200, complete.get_json()
    assert complete.get_json()["status"] == "OK"
    assert simple_storage["email"] == "user@example.com"

    stored = [authenticator.stored_credential_entry()]
    auth_begin = client.post(
        "/api/authenticate/begin?email=user@example.com", json={"credentials": stored}
    )
    assert auth_begin.status_code == 200
    auth_challenge = unb64u(auth_begin.get_json()["publicKey"]["challenge"])

    auth_complete = client.post(
        "/api/authenticate/complete?email=user@example.com",
        json=assertion_payload(authenticator, challenge=auth_challenge),
        headers={"Origin": ORIGIN},
    )
    assert auth_complete.status_code == 200, auth_complete.get_json()
    assert auth_complete.get_json()["status"] == "OK"


# --------------------------------------------------------------------------
# The advanced flow stays permissive -- but always honest.
# --------------------------------------------------------------------------


def test_advanced_register_complete_reports_server_session_challenge_source(
    config_module, advanced_module, advanced_storage
):
    authenticator = Authenticator()
    client = config_module.app.test_client()
    challenge = b"\x31" * 32

    begin = client.post(
        "/api/advanced/register/begin",
        json={"publicKey": advanced_public_key_options(challenge=challenge)},
    )
    assert begin.status_code == 200, begin.get_json()
    body = begin.get_json()
    server_challenge = unb64u(body["publicKey"]["challenge"])

    complete = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(challenge=server_challenge),
            "__credential_response": registration_payload(
                authenticator, challenge=server_challenge
            ),
            "__session_state": body["__session_state"],
        },
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
    payload = complete.get_json()
    assert payload["status"] == "OK"
    # The session state took precedence, and the response says so.
    assert payload["challengeSource"] == "server-session"


def test_advanced_register_complete_reports_client_supplied_challenge_source(
    config_module, advanced_module, advanced_storage
):
    """The request editor may supply its own state -- but it is labelled."""

    authenticator = Authenticator()
    client = config_module.app.test_client()
    client_challenge = b"\x77" * 32

    # No /begin call: a cold request carrying its own state, as the editor does.
    complete = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(challenge=client_challenge),
            "__credential_response": registration_payload(
                authenticator, challenge=client_challenge
            ),
            "__session_state": {
                "challenge": b64u(client_challenge),
                "user_verification": "discouraged",
            },
        },
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
    payload = complete.get_json()
    assert payload["status"] == "OK"
    # It worked -- and the response is explicit about why it was trusted.
    assert payload["challengeSource"] == "client-supplied"


def test_advanced_complete_always_reports_challenge_source_even_on_error(
    config_module, advanced_module
):
    client = config_module.app.test_client()

    response = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(challenge=b"\x01" * 32),
            "__credential_response": {
                "id": "AQID",
                "rawId": "AQID",
                "type": "public-key",
                "response": {"clientDataJSON": "AQID", "attestationObject": "AQID"},
            },
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    assert "challengeSource" in response.get_json()
