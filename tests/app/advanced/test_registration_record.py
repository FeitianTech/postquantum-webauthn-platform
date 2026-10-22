"""Tests for the record a verified advanced registration builds."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from fido2.webauthn import AuthenticatorData

from server.app.routes.advanced import (
    registration_record as advanced_registration_record,
)
from tests.app.entry_app import entry_app
from tests.app.security.ceremony_helpers import RP_ID, Authenticator

from .registration_ceremony import register


def _with_public_key(public_key):
    return SimpleNamespace(credential_data=SimpleNamespace(public_key=public_key))


@pytest.mark.parametrize(
    ("requested", "reported"),
    [
        (2, "userVerificationOptionalWithCredentialIDList"),
        ("custom-policy", "custom-policy"),
    ],
)
def test_the_requested_cred_protect_policy_is_reported_by_name(advanced_stores, requested, reported):
    response = register(entry_app().test_client(), public_key_changes={"extensions": {"credProtect": requested}})

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["credProtectUsed"] == reported


@pytest.mark.parametrize(
    ("public_key", "algorithm", "name"),
    [
        ({3: -8}, -8, "EdDSA"),
        ({"alg": -7}, -7, "ES256 (ECDSA)"),
        ({1: 2}, None, "Unknown"),
        ([None, None, None, -8], -8, "EdDSA"),
        (None, None, "Unknown"),
    ],
)
def test_the_algorithm_is_read_from_the_keys_label_three_or_its_alg(public_key, algorithm, name):
    credential_info = {}

    resolved = advanced_registration_record.resolve_algorithm(credential_info, _with_public_key(public_key))

    assert resolved == (algorithm, name)
    assert credential_info["publicKeyAlgorithm"] == algorithm


def test_a_key_that_does_not_encode_has_no_public_key_encodings():
    assert advanced_registration_record._public_key_encodings(_with_public_key({1: object()})) == (None, None)
    assert advanced_registration_record._public_key_encodings(_with_public_key(None)) == (None, None)


def test_an_rp_id_hash_the_checks_left_open_is_compared_with_the_rp_id():
    auth_data = AuthenticatorData(Authenticator().authenticator_data())

    def _facts(rp_id):
        return advanced_registration_record._registration_facts(
            auth_data=auth_data,
            credential_info={"properties": {}, "registration_time": time.time()},
            client_extension_results={},
            resolved_rp_id=rp_id,
            attestation_rp_id_hash_valid=None,
        )

    assert _facts(RP_ID).rp_id_hash_valid is True
    assert _facts("other.example").rp_id_hash_valid is False


def test_a_registration_without_cred_props_reports_no_resident_key(advanced_stores):
    # The authenticator verified the user (UV) and the request required a resident key:
    # neither says whether the credential is discoverable.
    response = register(
        entry_app().test_client(), public_key_changes={"authenticatorSelection": {"residentKey": "required"}}
    )

    assert response.status_code == 200, response.get_json()
    answer = response.get_json()
    assert answer["actualResidentKey"] is None
    assert "residentKey" not in answer["storedCredential"]
    assert answer["storedCredential"]["properties"]["residentKey"] is None
    assert "residentKey" not in answer["relyingParty"]


# What the attestation checks concluded, as build_debug_info reads it.
_ANALYSIS = {
    "signatureValid": True,
    "rootValid": None,
    "rpIdHashValid": True,
    "aaguidMatch": None,
    "checksSafe": {},
    "summary": {},
    "errors": [],
}


@pytest.mark.parametrize("resident", [True, False])
def test_the_resident_key_reported_and_stored_is_the_browsers_cred_props_rk(resident):
    credential_info = {"properties": {}, "registration_time": time.time()}
    auth_data = AuthenticatorData(Authenticator().authenticator_data())

    facts = advanced_registration_record._registration_facts(
        auth_data=auth_data,
        credential_info=credential_info,
        client_extension_results={"credProps": {"rk": resident}},
        resolved_rp_id=RP_ID,
        attestation_rp_id_hash_valid=None,
    )
    debug = advanced_registration_record.build_debug_info(
        public_key={},
        attestation_format="none",
        client_extension_results={"credProps": {"rk": resident}},
        analysis=_ANALYSIS,
        algo=-7,
        challenge_source="server-session",
    )

    assert facts.resident_key is resident
    assert credential_info["properties"]["residentKey"] is resident
    assert debug["actualResidentKey"] is resident
