"""A registration's attestation is read only once fido2 has accepted its ceremony.

``extract_attestation_details`` decodes, parses and hashes every x5c certificate a
registration response carries. Both tabs' completes call it only after the
session's ceremony state is consumed and fido2's ``register_complete`` accepted
the response: a request with no ceremony, or one fido2 refuses, never reaches it.
"""
from __future__ import annotations

import pytest

from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.entry_app import entry_app

from .ceremony_helpers import ORIGIN, Authenticator, registration_payload

STATE_NOT_FOUND = "Registration state not found or has expired. Please restart the registration process."


@pytest.fixture
def attestation_reads(monkeypatch) -> list:
    """Every call to ``extract_attestation_details``, each failing the request that made it."""

    calls: list = []

    def _read_too_early(response):
        calls.append(response)
        raise AssertionError("the attestation was read before fido2 accepted the ceremony")

    monkeypatch.setattr(attestation_certificates, "extract_attestation_details", _read_too_early)
    return calls


def test_a_simple_complete_without_a_ceremony_never_reads_the_attestation(attestation_reads, simple_storage):
    response = entry_app().test_client().post(
        "/api/register/complete?email=user@example.com",
        json=registration_payload(Authenticator(), challenge=b"\x01" * 32),
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": STATE_NOT_FOUND}
    assert attestation_reads == []


def test_a_simple_complete_fido2_refuses_never_reads_the_attestation(attestation_reads, simple_storage):
    client = entry_app().test_client()
    begin = client.post("/api/register/begin?email=user@example.com", json={"credentials": []})
    assert begin.status_code == 200

    response = client.post(
        "/api/register/complete?email=user@example.com",
        json=registration_payload(Authenticator(), challenge=b"not the challenge begin issued"),
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Wrong challenge in response."}
    assert attestation_reads == []
