"""Tests for the record a verified simple registration builds."""
from __future__ import annotations

from fido2.webauthn import AuthenticatorData

from server.app.encoding import encode_base64url
from server.app.routes.simple import registration_record as simple_registration_record
from tests.app.security.ceremony_helpers import RP_ID, Authenticator

USER_ID = bytes(range(32))


class _AuthenticatorDataWithoutBytes(AuthenticatorData):
    def __bytes__(self):
        raise ValueError("these authenticator data have no bytes")


def _registration(*, auth_data_class=AuthenticatorData, **changes):
    fields = {
        "uname": "user@example.com",
        "user_id": USER_ID,
        "exclude_credentials_count": 0,
        "response": {},
        "attestation_format": "none",
        "attestation_statement": {},
        "parsed_attestation_object": None,
        "attestation_certificate_details": None,
        "attestation_certificates_details": [],
        "client_data_json": "",
        "client_extension_results": {},
        "min_pin_length_value": None,
        "auth_data": auth_data_class(Authenticator().authenticator_data(counter=3)),
        "authenticator_attachment_response": None,
        "raw_attestation_object_b64": "",
        "resolved_rp_id": RP_ID,
        "attestation_signature_valid": None,
        "attestation_root_valid": None,
        "attestation_rp_id_hash_valid": True,
        "attestation_aaguid_match": None,
        "attestation_checks_safe": {"warnings": []},
        **changes,
    }
    return simple_registration_record.SimpleRegistration(**fields)


def test_attestation_warnings_are_trimmed_and_blank_ones_dropped():
    reg = _registration(attestation_checks_safe={"warnings": ["  keep me  ", "   ", {"code": "W1"}, None]})

    simple_registration_record.initialize_registration_context(reg)

    assert reg.warnings == ["keep me"]
    assert reg.attestation_summary["warnings"] == ["keep me", {"code": "W1"}]
    assert reg.credential_properties["attestationWarnings"] == ["keep me"]


def test_checks_without_a_warning_list_add_no_warnings():
    reg = _registration(attestation_checks_safe={})

    simple_registration_record.initialize_registration_context(reg)

    assert reg.warnings == []
    assert "warnings" not in reg.attestation_summary
    assert "attestationWarnings" not in reg.credential_properties


def test_an_rp_id_hash_the_checks_left_open_is_compared_with_the_rp_id():
    matching = _registration(attestation_rp_id_hash_valid=None)
    other = _registration(attestation_rp_id_hash_valid=None, resolved_rp_id="other.example")

    for reg in (matching, other):
        simple_registration_record.initialize_registration_context(reg)
        simple_registration_record.populate_authenticator_data_context(reg)

    assert matching.attestation_rp_id_hash_valid is True
    assert other.attestation_rp_id_hash_valid is False


def test_authenticator_data_without_bytes_leave_their_fields_empty():
    reg = _registration(auth_data_class=_AuthenticatorDataWithoutBytes)

    simple_registration_record.initialize_registration_context(reg)
    simple_registration_record.populate_authenticator_data_context(reg)

    assert (reg.authenticator_data_raw, reg.authenticator_data_hex, reg.authenticator_data_hash) == ("", "", "")
    assert "authenticatorDataHash" not in reg.credential_properties
    assert reg.algoname == "ES256 (ECDSA)"


def test_the_record_keeps_the_accounts_user_handle_and_names_it_by_its_username():
    reg = _registration()

    simple_registration_record.initialize_registration_context(reg)
    simple_registration_record.populate_authenticator_data_context(reg)
    simple_registration_record.populate_rp_debug_context(reg)
    simple_registration_record.build_stored_credential_context(reg)

    assert reg.credential_info["user_info"] == {
        "name": "user@example.com",
        "display_name": "user@example.com",
        "user_handle": USER_ID,
    }
    assert reg.rp_info["userHandle"]["hex"] == USER_ID.hex()
    assert reg.stored_credential["userHandle"] == encode_base64url(USER_ID)
    assert (reg.stored_credential["userName"], reg.stored_credential["displayName"]) == ("user@example.com", "user@example.com")


def test_the_record_says_how_many_credentials_begin_excluded():
    excluding = _registration(exclude_credentials_count=2)
    excluding_none = _registration()

    for reg in (excluding, excluding_none):
        simple_registration_record.initialize_registration_context(reg)
        simple_registration_record.populate_authenticator_data_context(reg)
        simple_registration_record.populate_rp_debug_context(reg)

    assert excluding.credential_properties["excludeCredentialsSentCount"] == 2
    assert excluding.debug_info["excludeCredentialsUsed"] is True
    assert excluding_none.credential_properties["excludeCredentialsSentCount"] == 0
    assert excluding_none.debug_info["excludeCredentialsUsed"] is False
