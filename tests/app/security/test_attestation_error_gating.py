"""Which attestation findings refuse a registration, and which are only reported.

``perform_attestation_checks`` lists every failure it finds in ``errors``. The
Simple tab refuses a registration on an integrity error alone
(``error_codes.INTEGRITY_ERRORS``: the response is not the one the request asked
for, or its attestation statement does not verify); every other finding, about
the trust path, its root or the metadata, is answered and stored as a warning.
The Advanced tab completes either way and reports every one as an error.
"""
from __future__ import annotations

import json
import uuid

from cryptography.hazmat.primitives.asymmetric import ec

from server.app.mds import verifier as mds_verifier
from tests.app.characterization import material
from tests.app.entry_app import entry_app
from tests.app.metadata import mds_fixture

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
    # What this browser keeps of the credential carries them too.
    kept = body["storedCredential"]["properties"]
    assert kept["attestationWarnings"] == ["metadata_not_available", "trust_path_missing"]


def test_with_metadata_a_self_attestation_registers_with_no_root_as_a_warning(simple_storage, mds_fixture_snapshot):
    response = complete_simple_registration(entry_app().test_client(), Authenticator(), attestation="packed")

    assert response.status_code == 200, response.get_json()
    checks = response.get_json()["relyingParty"]["registrationData"]["attestationChecks"]
    assert checks["errors"] == []
    assert checks["warnings"] == ["trust_path_missing", "attestation_root_not_found", "metadata_entry_missing"]
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


# --------------------------------------------------------------------------
# An MDS status that says the authenticator is not to be trusted.
# --------------------------------------------------------------------------


def _verifier_where_l1_says(status):
    """The fixture snapshot's verifier, its L1 entry's latest report saying ``status``."""

    payload = json.loads((mds_fixture.SNAPSHOT_DIR / "fido-mds3.verified.json").read_text(encoding="utf-8"))
    l1 = str(uuid.UUID(bytes=ES256_AND_EDDSA_AAGUID))
    entries = [
        {**raw, "statusReports": [*raw["statusReports"], {"status": status, "effectiveDate": "2026-10-01"}]}
        if raw.get("aaguid") == l1
        else raw
        for raw in payload["entries"]
    ]
    return mds_verifier.IndexedVerifier(mds_verifier.PackagedEntries(entries))


L1_CERTIFICATION = "FIDO Certified L1 • Fixture Security Key • (FIDO20020260901001)"


def test_an_unsafe_mds_status_is_a_simple_warning_and_the_record_keeps_the_status(simple_storage, monkeypatch):
    monkeypatch.setattr(mds_verifier, "get_mds_verifier", lambda: _verifier_where_l1_says("USER_VERIFICATION_BYPASS"))

    response = complete_simple_registration(entry_app().test_client(), Authenticator(aaguid=ES256_AND_EDDSA_AAGUID))

    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    checks = body["relyingParty"]["registrationData"]["attestationChecks"]
    assert checks["errors"] == []
    assert checks["warnings"] == ["metadata_status_unsafe: USER_VERIFICATION_BYPASS"]
    kept = body["storedCredential"]["properties"]["attestationSummary"]["metadata"]
    assert (kept["latest_status"], kept["certification_level"]) == ("USER Verification Bypass", L1_CERTIFICATION)


def test_an_unsafe_mds_status_is_an_advanced_error_and_the_record_keeps_the_status(advanced_storage, monkeypatch):
    monkeypatch.setattr(mds_verifier, "get_mds_verifier", lambda: _verifier_where_l1_says("ATTESTATION_KEY_COMPROMISE"))
    authenticator = Authenticator(aaguid=ES256_AND_EDDSA_AAGUID)
    client = entry_app().test_client()

    begin = client.post("/api/advanced/register/begin", json={"publicKey": advanced_public_key_options(challenge=b"\x54" * 32)})
    server_challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(challenge=server_challenge),
            "__credential_response": registration_payload(authenticator, challenge=server_challenge),
        },
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
    payload = complete.get_json()
    assert payload["attestationErrors"] == ["metadata_status_unsafe: ATTESTATION_KEY_COMPROMISE"]
    kept = payload["storedCredential"]["properties"]["attestationSummary"]["metadata"]
    assert (kept["latest_status"], kept["certification_level"]) == ("Attestation KEY Compromise", L1_CERTIFICATION)
