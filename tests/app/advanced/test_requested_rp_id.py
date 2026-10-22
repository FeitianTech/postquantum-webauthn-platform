"""An RP ID an Advanced request names, used by both ceremonies from begin to complete.

The site at https://app.example.com is configured with the RP ID app.example.com;
its requests name example.com, a registrable suffix of its host.
"""
from __future__ import annotations

import hashlib

import pytest

from tests.app.security.ceremony_helpers import (
    Authenticator,
    advanced_public_key_options,
    assertion_payload,
    b64u,
    registration_payload,
    unb64u,
)

SITE = "https://app.example.com"
REQUESTED = "example.com"


@pytest.fixture
def site(make_app, advanced_stores):
    app = make_app({"FIDO_SERVER_ALLOWED_ORIGINS": SITE, "FIDO_SERVER_RP_ID": "app.example.com"})
    return app.test_client()


def _post(client, path, body):
    return client.post(path, json=body, base_url=SITE, headers={"Origin": SITE})


def _register(client, authenticator):
    begin = _post(
        client,
        "/api/advanced/register/begin",
        {"publicKey": advanced_public_key_options(challenge=b"\x73" * 32, rp_id=REQUESTED)},
    )
    assert begin.status_code == 200, begin.get_json()
    assert begin.get_json()["publicKey"]["rp"]["id"] == REQUESTED
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    return _post(
        client,
        "/api/advanced/register/complete",
        {
            "publicKey": advanced_public_key_options(challenge=challenge, rp_id=REQUESTED),
            "__credential_response": registration_payload(
                authenticator, challenge=challenge, origin=SITE, rp_id=REQUESTED
            ),
        },
    )


def _authenticate(client, authenticator, entry, **rp_id):
    allow = [{"type": "public-key", "id": {"$base64url": entry["credentialId"]}}]
    public_key = {"allowCredentials": allow, **rp_id}
    begin = _post(
        client,
        "/api/advanced/authenticate/begin",
        {"publicKey": {"challenge": {"$base64url": b64u(b"\x71" * 32)}, **public_key}, "__storedCredentials": [entry]},
    )
    assert begin.status_code == 200, begin.get_json()
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = _post(
        client,
        "/api/advanced/authenticate/complete",
        {
            "publicKey": {"challenge": {"$base64url": b64u(challenge)}, **public_key},
            "__assertion_response": assertion_payload(authenticator, challenge=challenge, origin=SITE, rp_id=REQUESTED),
            "__storedCredentials": [entry],
        },
    )
    return begin.get_json()["publicKey"]["rpId"], complete


def test_a_credential_registered_for_a_requested_rp_id_authenticates_for_it(site):
    authenticator = Authenticator()

    registration = _register(site, authenticator)
    assert registration.status_code == 200, registration.get_json()
    entry = registration.get_json()["storedCredential"]
    expected_hash = hashlib.sha256(REQUESTED.encode()).hexdigest()
    assert entry["properties"]["rpIdHash"] == entry["properties"]["rpIdHashExpected"] == expected_hash

    rp_id, assertion = _authenticate(site, authenticator, entry, rpId=REQUESTED)

    assert rp_id == REQUESTED
    assert assertion.status_code == 200, assertion.get_json()
    assert assertion.get_json()["verified"] is True


def test_complete_verifies_for_the_rp_id_its_begin_used(site):
    authenticator = Authenticator()
    entry = _register(site, authenticator).get_json()["storedCredential"]

    # A begin naming no RP ID is for the configured one, and so is its complete,
    # whatever RP ID the assertion was made for.
    rp_id, assertion = _authenticate(site, authenticator, entry)

    assert rp_id == "app.example.com"
    assert assertion.status_code == 400
    assert assertion.get_json()["error"] == "Wrong RP ID hash in response."
