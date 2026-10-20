"""``webauthn.attestation.error_codes``: how an attestation check's finding is written."""
from __future__ import annotations

import pytest
from fido2.attestation import InvalidData, InvalidSignature, UnsupportedType

from server.app.webauthn.attestation import error_codes


def test_a_finding_gives_the_exceptions_message_after_its_code():
    assert error_codes.with_reason("cose_key_error", KeyError(3)) == "cose_key_error: 3"


@pytest.mark.parametrize("exc", [InvalidSignature(), ValueError(""), ValueError("  ")])
def test_an_exception_without_a_message_gives_the_bare_code(exc):
    assert error_codes.with_reason("attestation_invalid", exc) == "attestation_invalid"


@pytest.mark.parametrize(
    ("exc", "finding"),
    [
        (UnsupportedType(None, "compound"), 'unsupported_attestation: Attestation format "compound" is not supported'),
        (InvalidSignature(), "attestation_invalid"),
        (InvalidData("Nonce does not match!"), "attestation_invalid: Nonce does not match!"),
        (TypeError("not bytes"), "attestation_error: not bytes"),
    ],
)
def test_a_statement_fido2_refuses_is_named_for_why(exc, finding):
    assert error_codes.statement_error(exc) == finding


@pytest.mark.parametrize(
    ("exc", "finding"),
    [
        (InvalidSignature(), "certificate_chain_invalid"),
        (ValueError("error parsing asn1 value"), "certificate_chain_unreadable: error parsing asn1 value"),
    ],
)
def test_a_chain_that_does_not_verify_is_named_for_why(exc, finding):
    assert error_codes.chain_error(exc) == finding


def test_the_simple_tab_refuses_on_these_errors_alone():
    assert error_codes.INTEGRITY_ERRORS == {
        "registration_response_invalid",
        "registration_parse_error",
        "client_data_type_invalid",
        "challenge_mismatch",
        "origin_mismatch",
        "cross_origin_not_allowed",
        "rp_id_hash_mismatch",
        "user_presence_missing",
        "user_verification_required_not_satisfied",
        "attested_credential_data_missing",
        "algorithm_not_allowed",
        "cose_key_error",
        "unsupported_attestation",
        "attestation_invalid",
        "attestation_error",
        "attestation_signature_invalid",
    }


@pytest.mark.parametrize(
    "finding",
    [
        "trust_path_missing",
        "certificate_chain_invalid",
        "certificate_chain_unreadable: error parsing asn1 value",
        "certificate_parse_error: error parsing asn1 value",
        "certificate_out_of_validity: CN=Leaf",
        "No root found for Authenticator",
        "metadata_lookup_failed: metadata unreachable",
        "metadata_entry_missing",
        "metadata_not_fido_trusted",
        "attestation_root_not_trusted",
        "algorithm_not_in_metadata",
    ],
)
def test_what_an_attestation_proves_about_the_authenticator_is_no_integrity_error(finding):
    assert error_codes.error_code(finding) not in error_codes.INTEGRITY_ERRORS


def test_a_finding_with_a_reason_has_the_code_before_it():
    assert error_codes.error_code("cose_key_error: 3") == "cose_key_error"
    assert error_codes.error_code("No root found for Authenticator") == "No root found for Authenticator"


def test_integrity_errors_stay_errors_and_the_others_follow_the_warnings_in_order():
    results = {
        "root_valid": None,
        "errors": ["trust_path_missing", "cose_key_error: 3", "metadata_entry_missing", "origin_mismatch"],
        "warnings": ["metadata_not_available"],
    }

    assert error_codes.integrity_errors_only(results) == {
        "root_valid": None,
        "errors": ["cose_key_error: 3", "origin_mismatch"],
        "warnings": ["metadata_not_available", "trust_path_missing", "metadata_entry_missing"],
    }
    assert results["errors"] == ["trust_path_missing", "cose_key_error: 3", "metadata_entry_missing", "origin_mismatch"]
    assert results["warnings"] == ["metadata_not_available"]


def test_findings_without_a_warnings_list_start_one():
    assert error_codes.integrity_errors_only({"errors": ["trust_path_missing"]}) == {
        "errors": [],
        "warnings": ["trust_path_missing"],
    }


def test_results_without_an_errors_list_are_left_as_they_are():
    assert error_codes.integrity_errors_only({"signature_valid": True, "warnings": []}) == {
        "signature_valid": True,
        "warnings": [],
    }
