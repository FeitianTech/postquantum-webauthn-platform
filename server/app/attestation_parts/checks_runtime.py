from __future__ import annotations

from typing import Any, Dict, Mapping, Optional


def perform_attestation_checks(
    response: Mapping[str, Any],
    state: Optional[Mapping[str, Any]],
    public_key_options: Optional[Mapping[str, Any]],
    auth_data: Optional[Any],
    expected_origin: str,
    rp_id: str,
) -> Dict[str, Any]:
    """Execute a comprehensive set of attestation validation checks."""

    results: Dict[str, Any] = {
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

    if not isinstance(response, Mapping):
        results["errors"].append("registration_response_invalid")
        return results

    try:
        registration = RegistrationResponse.from_dict(response)
    except Exception as exc:
        results["errors"].append(f"registration_parse_error: {exc}")
        return results

    client_data = registration.response.client_data
    attestation_object = registration.response.attestation_object
    results["attestation_format"] = attestation_object.fmt

    if isinstance(auth_data, AuthenticatorData):
        auth_data_obj = auth_data
    else:
        auth_data_obj = attestation_object.auth_data

    expected_challenge_bytes = _resolve_expected_challenge(state, public_key_options)
    _populate_client_data_results(
        results,
        client_data=client_data,
        expected_challenge_bytes=expected_challenge_bytes,
        expected_origin=expected_origin,
    )

    _populate_rp_id_hash_result(results, auth_data_obj=auth_data_obj, rp_id=rp_id)

    auth_ctx = _populate_authenticator_data_results(
        results,
        auth_data_obj=auth_data_obj,
        state=state,
        public_key_options=public_key_options,
    )

    client_data_hash = client_data.hash
    verification_data = bytes(auth_data_obj) + client_data_hash
    results["hash_binding"] = {
        "client_data_hash": encode_base64url(client_data_hash),
        "verification_data": encode_base64url(verification_data),
    }

    signature_ctx = _resolve_signature_validation(attestation_object, client_data_hash)
    for error_message in signature_ctx["attestation_errors"]:
        results["errors"].append(error_message)

    results["signature_valid"] = signature_ctx["signature_valid"]

    root_ctx = _evaluate_root_validation(
        results,
        algorithm=auth_ctx["algorithm"],
        attestation_object=attestation_object,
        attestation_result=signature_ctx["attestation_result"],
        client_data_hash=client_data_hash,
        credential_aaguid_bytes=auth_ctx["credential_aaguid_bytes"],
        signature_valid=signature_ctx["signature_valid"],
        attestation_format_value=signature_ctx["attestation_format_value"],
    )

    _finalize_metadata_results(
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
