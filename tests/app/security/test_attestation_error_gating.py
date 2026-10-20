"""Which attestation findings refuse a registration, and which are only reported.

``perform_attestation_checks`` lists every failure it finds in ``errors``. The
Simple tab refuses a registration on an integrity error alone
(``error_codes.INTEGRITY_ERRORS``: the response is not the one the request asked
for, or its attestation statement does not verify); every other finding, about
the trust path, its root or the metadata, is answered and stored as a warning.
The Advanced tab completes either way and reports every one as an error.
"""
from __future__ import annotations

import uuid

from cryptography.hazmat.primitives.asymmetric import ec

from tests.app.characterization import material
from tests.app.entry_app import entry_app

from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    advanced_public_key_options,
    complete_simple_registration,
    registration_payload,
    unb64u,
)

# The fixture snapshot's entry whose getInfo lists ES256 and EdDSA, and no other algorithm.
ES256_AND_EDDSA_AAGUID = uuid.UUID("f1d0f1d0-0000-4000-8000-000000000001").bytes

# --------------------------------------------------------------------------
# NEGATIVE -- the simple flow gates on errors.
# --------------------------------------------------------------------------


def test_simple_register_complete_rejects_cross_origin_registration(simple_storage):
    """``crossOrigin: true`` produces a real error that must now gate."""

    authenticator = Authenticator()
    client = entry_app().test_client()

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


def test_simple_register_complete_rejects_origin_mismatch(simple_storage):
    """An origin the server did not expect must gate, not just be noted."""

    authenticator = Authenticator()
    client = entry_app().test_client()

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


def test_a_simple_refusal_lists_only_the_integrity_errors(simple_storage):
    """A cross-origin self attestation also has no trust path: only the integrity error is the refusal's."""

    response = complete_simple_registration(entry_app().test_client(), Authenticator(), attestation="packed", cross_origin=True)

    assert response.status_code == 400
    assert response.get_json()["attestationErrors"] == ["cross_origin_not_allowed"]
    assert simple_storage == {}


def test_a_simple_registration_whose_attestation_signature_does_not_verify_is_refused(simple_storage):
    """fido2 does not verify the attestation statement here: the statement check is what refuses it."""

    authenticator = Authenticator()
    certificate = material.attestation_leaf_certificate(authenticator.aaguid)

    response = complete_simple_registration(
        entry_app().test_client(),
        authenticator,
        attestation="packed",
        attestation_key=ec.generate_private_key(ec.SECP256R1()),
        x5c=[certificate],
    )

    assert response.status_code == 400
    assert response.get_json()["attestationErrors"] == ["attestation_invalid", "attestation_signature_invalid"]
    assert simple_storage == {}


# --------------------------------------------------------------------------
# POSITIVE -- a clean ceremony reports no errors and still succeeds.
# --------------------------------------------------------------------------


def test_clean_simple_registration_reports_no_attestation_errors(simple_storage):
    authenticator = Authenticator()
    client = entry_app().test_client()

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


def test_a_packed_self_attestation_registers_in_the_simple_tab_with_its_trust_findings_as_warnings(simple_storage):
    response = complete_simple_registration(entry_app().test_client(), Authenticator(), attestation="packed")

    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    checks = body["relyingParty"]["registrationData"]["attestationChecks"]
    assert checks["signature_valid"] is True
    assert checks["errors"] == []
    assert checks["warnings"] == ["metadata_not_available", "trust_path_missing"]
    assert body["warnings"] == ["metadata_not_available", "trust_path_missing"]
    stored = simple_storage["credentials"][-1]["properties"]
    assert stored["attestationWarnings"] == ["metadata_not_available", "trust_path_missing"]


def test_with_metadata_a_self_attestation_registers_with_no_root_as_a_warning(simple_storage, mds_fixture_snapshot):
    response = complete_simple_registration(entry_app().test_client(), Authenticator(), attestation="packed")

    assert response.status_code == 200, response.get_json()
    checks = response.get_json()["relyingParty"]["registrationData"]["attestationChecks"]
    assert checks["errors"] == []
    assert checks["warnings"] == ["trust_path_missing", "No root found for Authenticator", "metadata_entry_missing"]
    assert checks["root_valid"] is None


# --------------------------------------------------------------------------
# The advanced flow surfaces errors instead of dropping them.
# --------------------------------------------------------------------------


def test_advanced_register_complete_surfaces_attestation_errors(advanced_storage):
    """The advanced tab may still complete, but must report what failed."""

    authenticator = Authenticator()
    client = entry_app().test_client()
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


def test_advanced_register_complete_reports_verified_when_clean(advanced_storage):
    authenticator = Authenticator()
    client = entry_app().test_client()
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
        },
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
    payload = complete.get_json()
    assert payload["status"] == "OK"
    assert payload["attestationErrors"] == []
    assert payload["attestationVerified"] is True


# --------------------------------------------------------------------------
# An algorithm the authenticator's metadata does not list.
# --------------------------------------------------------------------------


def test_an_algorithm_the_metadata_does_not_list_is_a_simple_warning(simple_storage, mds_fixture_snapshot):
    authenticator = Authenticator(key_type="es384", aaguid=ES256_AND_EDDSA_AAGUID)

    response = complete_simple_registration(entry_app().test_client(), authenticator)

    assert response.status_code == 200, response.get_json()
    checks = response.get_json()["relyingParty"]["registrationData"]["attestationChecks"]
    assert checks["metadata"]["algorithm_supported"] is False
    assert checks["errors"] == []
    assert checks["warnings"] == ["algorithm_not_in_metadata"]


def test_an_algorithm_the_metadata_does_not_list_is_an_advanced_error(advanced_storage, mds_fixture_snapshot):
    authenticator = Authenticator(key_type="es384", aaguid=ES256_AND_EDDSA_AAGUID)
    client = entry_app().test_client()
    options = {"challenge": b"\x53" * 32, "algorithms": (-35,)}

    begin = client.post("/api/advanced/register/begin", json={"publicKey": advanced_public_key_options(**options)})
    server_challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(**{**options, "challenge": server_challenge}),
            "__credential_response": registration_payload(authenticator, challenge=server_challenge),
        },
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
    payload = complete.get_json()
    assert payload["attestationErrors"] == ["algorithm_not_in_metadata"]
    assert payload["attestationVerified"] is False
    assert payload["attestationSummary"]["metadata"]["algorithm_supported"] is False
