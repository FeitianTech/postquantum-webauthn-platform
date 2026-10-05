"""Every check of a registration's attestation, in order: the request's expectations
(``request_expectations``), the response against them (``response_checks``), the
attestation statement (``statement_checks``) and the MDS metadata (``metadata_checks``)."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fido2.webauthn import AuthenticatorData, RegistrationResponse

from . import metadata_checks, request_expectations, response_checks, statement_checks


def _empty_results() -> dict[str, Any]:
    return {
        "attestation_format": None,
        "signature_valid": None,
        "root_valid": None,
        "rp_id_hash_valid": None,
        "aaguid_match": None,
        "client_data": {},
        "authenticator_data": {},
        "metadata": {},
        "hash_binding": {},
        "errors": [],
        "warnings": [],
    }


def _parse_registration(response: Any, results: dict[str, Any]) -> RegistrationResponse | None:
    """The response as fido2 reads it, or None with the reason in ``results``."""

    if not isinstance(response, Mapping):
        results["errors"].append("registration_response_invalid")
        return None
    try:
        return RegistrationResponse.from_dict(response)
    except Exception as exc:
        results["errors"].append(f"registration_parse_error: {exc}")
        return None


def perform_attestation_checks(
    response: Mapping[str, Any],
    state: Mapping[str, Any] | None,
    public_key_options: Mapping[str, Any] | None,
    auth_data: Any | None,
    expected_origin: str,
    rp_id: str,
) -> dict[str, Any]:
    """Execute a comprehensive set of attestation validation checks."""

    results = _empty_results()
    registration = _parse_registration(response, results)
    if registration is None:
        return results

    client_data = registration.response.client_data
    attestation_object = registration.response.attestation_object
    results["attestation_format"] = attestation_object.fmt
    # The authenticator data the caller already holds, else the attestation object's.
    auth_data_obj = auth_data if isinstance(auth_data, AuthenticatorData) else attestation_object.auth_data

    expected_challenge_bytes = request_expectations.resolve_expected_challenge(state, public_key_options)
    response_checks.populate_client_data_results(
        results,
        client_data=client_data,
        expected_challenge_bytes=expected_challenge_bytes,
        expected_origin=expected_origin,
    )

    response_checks.populate_rp_id_hash_result(results, auth_data_obj=auth_data_obj, rp_id=rp_id)

    auth_ctx = response_checks.populate_authenticator_data_results(
        results,
        auth_data_obj=auth_data_obj,
        state=state,
        public_key_options=public_key_options,
    )

    client_data_hash = client_data.hash
    results["hash_binding"] = response_checks.hash_binding(auth_data_obj, client_data_hash)

    signature_ctx = statement_checks.resolve_signature_validation(attestation_object, client_data_hash)
    statement_checks.record_signature_result(results, signature_ctx)

    root_ctx = statement_checks.evaluate_root_validation(
        results,
        attestation_object=attestation_object,
        attestation_result=signature_ctx["attestation_result"],
        client_data_hash=client_data_hash,
        signature_valid=signature_ctx["signature_valid"],
        attestation_format_value=signature_ctx["attestation_format_value"],
    )

    metadata_checks.finalize_metadata_results(
        results,
        metadata_entry=root_ctx["metadata_entry"],
        metadata_lookup_source=root_ctx["metadata_lookup_source"],
        verifier=root_ctx["verifier"],
        credential_aaguid_bytes=auth_ctx["credential_aaguid_bytes"],
        certificate_aaguid_bytes=root_ctx["certificate_aaguid_bytes"],
        root_check_details=root_ctx["root_check_details"],
        root_valid=root_ctx["root_valid"],
    )

    return results
