"""Tests for what advanced register complete reads from its request."""
from __future__ import annotations

import json

import pytest

from server.app.config import request_limits
from server.app.routes import ceremony_errors
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    Authenticator,
    advanced_public_key_options,
    b64u,
    registration_payload,
    unb64u,
)

from .registration_ceremony import register


def _complete(body):
    return entry_app().test_client().post("/api/advanced/register/complete", json=body)


@pytest.mark.parametrize("body", [["publicKey"], "publicKey"])
def test_a_body_that_is_no_object_has_no_credential_response(body):
    response = _complete(body)

    assert response.status_code == 400
    assert response.get_json() == {"error": "Credential response is required"}


def test_a_member_of_the_wrong_type_is_refused_before_the_registration_is_verified():
    response = _complete(
        {
            "publicKey": {"challenge": "AQID", "user": {"name": "user@example.com"}, "extensions": None},
            "__credential_response": {"response": {}},
        }
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "extensions must be an object."}


@pytest.mark.parametrize("inner", ["attestation", ["attestation"]])
def test_a_response_member_that_is_no_object_is_read_as_none(inner):
    response = _complete(
        {"publicKey": {"challenge": "AQID", "user": {"name": "user@example.com"}}, "__credential_response": {"response": inner}}
    )

    assert response.status_code == 400
    assert response.get_json()["error"].startswith("Registration state not found")


def test_an_authenticator_selection_that_is_no_object_asks_for_no_resident_key(own_stores):
    response = register(entry_app().test_client(), public_key_changes={"authenticatorSelection": "not an object"})

    assert response.status_code == 200, response.get_json()
    properties = response.get_json()["storedCredential"]["properties"]
    assert properties["residentKeyRequested"] is None
    assert properties["residentKeyRequired"] is False


def test_client_extension_results_of_null_are_read_as_none_sent(own_stores):
    client = entry_app().test_client()
    begin = client.post("/api/advanced/register/begin", json={"publicKey": advanced_public_key_options(challenge=b"\x74" * 32)})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    credential = {**registration_payload(Authenticator(), challenge=challenge), "clientExtensionResults": None}

    response = client.post(
        "/api/advanced/register/complete",
        json={"publicKey": advanced_public_key_options(challenge=challenge), "__credential_response": credential},
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["storedCredential"]["properties"]["largeBlobClientOutput"] == {}


def test_a_state_whose_relying_party_is_gone_from_the_session_is_not_found():
    client = entry_app().test_client()
    begin = client.post("/api/advanced/register/begin", json={"publicKey": advanced_public_key_options(challenge=b"\x73" * 32)})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    with client.session_transaction() as session_state:
        del session_state["advanced_rp"]

    response = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(challenge=challenge),
            "__credential_response": registration_payload(Authenticator(), challenge=challenge),
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Registration state not found or has expired. Please restart the registration process.",
        "challengeSource": "server-session",
        "challengeStatus": "fresh",
    }


def _begin_with(client, public_key):
    begin = client.post("/api/advanced/register/begin", json={"publicKey": public_key})
    assert begin.status_code == 200, begin.get_json()
    return unb64u(begin.get_json()["publicKey"]["challenge"])


def _padded_response(challenge, size):
    """A genuinely signed credential response padded to exactly ``size`` bytes of compact JSON."""

    credential = registration_payload(Authenticator(), challenge=challenge)
    credential["padding"] = ""
    credential["padding"] = "x" * (size - len(json.dumps(credential, separators=(",", ":")).encode()))
    return credential


def test_a_credential_response_at_its_limit_is_read(make_app, own_stores):
    client = make_app({request_limits.REGISTRATION_RESPONSE_LIMIT_KEY: 4096}).test_client()
    challenge = _begin_with(client, advanced_public_key_options(challenge=b"\x73" * 32))

    response = client.post(
        "/api/advanced/register/complete",
        json={"publicKey": advanced_public_key_options(challenge=challenge), "__credential_response": _padded_response(challenge, 4096)},
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200, response.get_json()


def test_a_credential_response_over_its_limit_is_refused_with_its_size_and_nothing_is_stored(make_app, own_stores, tmp_path):
    client = make_app({request_limits.REGISTRATION_RESPONSE_LIMIT_KEY: 4096}).test_client()
    challenge = _begin_with(client, advanced_public_key_options(challenge=b"\x73" * 32))

    response = client.post(
        "/api/advanced/register/complete",
        json={"publicKey": advanced_public_key_options(challenge=challenge), "__credential_response": _padded_response(challenge, 4097)},
        headers={"Origin": ORIGIN},
    )

    # Refused once the ceremony's state is consumed, so with the challenge's trace.
    assert response.status_code == 413
    assert response.get_json() == {
        "error": (
            "This registration's response is 4,097 bytes, more than the 4,096 this server reads for one. "
            "Ask for no attestation and try again."
        ),
        "challengeSource": "server-session",
        "challengeStatus": "fresh",
    }
    assert list((tmp_path / "credential-artifacts").rglob("*.json")) == []


def test_a_credential_response_holding_a_lone_surrogate_is_measured_and_refused_as_unreadable(own_stores):
    client = entry_app().test_client()
    challenge = _begin_with(client, advanced_public_key_options(challenge=b"\x73" * 32))

    response = client.post(
        "/api/advanced/register/complete",
        json={"publicKey": advanced_public_key_options(challenge=challenge), "__credential_response": {"id": "\ud800"}},
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == ceremony_errors.REGISTRATION_FAILED


def test_the_editors_request_beside_the_response_is_not_measured(make_app, own_stores):
    client = make_app({request_limits.REGISTRATION_RESPONSE_LIMIT_KEY: 4096}).test_client()
    # Two fake exclude IDs of 4,096 bytes: the body is twice the limit, the response far under it.
    exclude = [{"type": "public-key", "id": {"$hex": (bytes([index]) * 4096).hex()}} for index in range(2)]
    public_key = {**advanced_public_key_options(challenge=b"\x73" * 32), "excludeCredentials": exclude}
    challenge = _begin_with(client, public_key)

    response = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": {**public_key, "challenge": {"$base64url": b64u(challenge)}},
            "__credential_response": registration_payload(Authenticator(), challenge=challenge),
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["storedCredential"]["properties"]["excludeCredentialsSentCount"] == 2
