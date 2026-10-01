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
            resident_key_required=False,
            attestation_rp_id_hash_valid=None,
        )

    assert _facts(RP_ID).rp_id_hash_valid is True
    assert _facts("other.example").rp_id_hash_valid is False
