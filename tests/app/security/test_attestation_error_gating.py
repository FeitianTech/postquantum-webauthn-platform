"""Fix 4 -- computed attestation failures must not return HTTP 200.

``perform_attestation_checks`` computes real failures into ``results["errors"]``
(``origin_mismatch``, ``cross_origin_not_allowed``, ``algorithm_not_allowed``,
``attestation_signature_invalid``, ``cose_key_error``), but the callers only
ever read ``signature_valid`` / ``root_valid`` / ``rp_id_hash_valid`` /
``aaguid_match`` / ``warnings``. ``errors`` was read nowhere, so a ceremony
with genuine failures still returned ``status: OK``.

The simple flow must now reject on a non-empty ``errors`` list; the advanced
flow may still complete, but must surface them.
"""
from __future__ import annotations

from .ceremony_helpers import (
    ORIGIN,
    RP_ID,
    Authenticator,
    advanced_public_key_options,
    registration_payload,
    unb64u,
)


# --------------------------------------------------------------------------
# NEGATIVE -- the simple flow gates on errors.
# --------------------------------------------------------------------------


def test_simple_register_complete_rejects_cross_origin_registration(
    config_module, simple_module, simple_storage
):
    """``crossOrigin: true`` produces a real error that must now gate."""

    authenticator = Authenticator()
    client = config_module.app.test_client()

    begin = client.post("/api/register/begin?email=user@example.com", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    response = client.post(
        "/api/register/complete?email=user@example.com",
        json=registration_payload(
            authenticator, challenge=challenge, cross_origin=True
        ),
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body.get("status") != "OK"
    assert body["verified"] is False
    assert "cross_origin_not_allowed" in body["attestationErrors"]
    # A gated ceremony must not persist a credential.
    assert simple_storage == {}


def test_simple_register_complete_rejects_origin_mismatch(
    config_module, simple_module, simple_storage
):
    """An origin the server did not expect must gate, not just be noted."""

    authenticator = Authenticator()
    client = config_module.app.test_client()

    begin = client.post(
        "/api/register/begin?email=user@example.com",
        json={"credentials": []},
        headers={"Host": "evil.example"},
    )
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    response = client.post(
        "/api/register/complete?email=user@example.com",
        json=registration_payload(
            authenticator,
            challenge=challenge,
            origin="https://evil.example",
            rp_id="evil.example",
        ),
        headers={"Host": "evil.example", "Origin": "https://evil.example"},
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body.get("status") != "OK"
    assert "origin_mismatch" in body["attestationErrors"]
    assert simple_storage == {}


# --------------------------------------------------------------------------
# POSITIVE -- a clean ceremony reports no errors and still succeeds.
# --------------------------------------------------------------------------


def test_clean_simple_registration_reports_no_attestation_errors(
    config_module, simple_module, simple_storage
):
    authenticator = Authenticator()
    client = config_module.app.test_client()

    begin = client.post("/api/register/begin?email=user@example.com", json={"credentials": []})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    response = client.post(
        "/api/register/complete?email=user@example.com",
        json=registration_payload(authenticator, challenge=challenge),
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body["status"] == "OK"
    checks = body["relyingParty"]["registrationData"]["attestationChecks"]
    assert checks["errors"] == []
    assert simple_storage["email"] == "user@example.com"


# --------------------------------------------------------------------------
# The advanced flow surfaces errors instead of dropping them.
# --------------------------------------------------------------------------


def test_advanced_register_complete_surfaces_attestation_errors(
    config_module, advanced_module, advanced_storage
):
    """The advanced tab may still complete, but must report what failed."""

    authenticator = Authenticator()
    client = config_module.app.test_client()
    challenge = b"\x51" * 32

    begin = client.post(
        "/api/advanced/register/begin",
        json={"publicKey": advanced_public_key_options(challenge=challenge)},
    )
    body = begin.get_json()
    server_challenge = unb64u(body["publicKey"]["challenge"])

    complete = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(challenge=server_challenge),
            "__credential_response": registration_payload(
                authenticator, challenge=server_challenge, cross_origin=True
            ),
            "__session_state": body["__session_state"],
        },
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
    payload = complete.get_json()
    # It completed -- and it is explicit that verification did not pass clean.
    assert "cross_origin_not_allowed" in payload["attestationErrors"]
    assert payload["attestationVerified"] is False
    assert payload["attestationSummary"]["errors"] == payload["attestationErrors"]
    assert payload["attestationSummary"]["verified"] is False


def test_advanced_register_complete_reports_verified_when_clean(
    config_module, advanced_module, advanced_storage
):
    authenticator = Authenticator()
    client = config_module.app.test_client()
    challenge = b"\x52" * 32

    begin = client.post(
        "/api/advanced/register/begin",
        json={"publicKey": advanced_public_key_options(challenge=challenge)},
    )
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
    assert payload["attestationErrors"] == []
    assert payload["attestationVerified"] is True
