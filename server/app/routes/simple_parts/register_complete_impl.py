from __future__ import annotations

from typing import Any, Dict, Mapping

from .register_complete_context_authenticator_impl import populate_authenticator_data_context_impl
from .register_complete_context_init_impl import initialize_registration_context_impl
from .register_complete_context_rp_debug_impl import populate_rp_debug_context_impl
from .register_complete_context_b_impl import (
    build_register_complete_response_payload_impl,
    build_stored_credential_context_impl,
    persist_registration_context_impl,
)


def register_complete_impl(simple_module: Any):
    uname = simple_module.request.args.get("email")
    response = simple_module.request.get_json(silent=True) or {}
    credential_response = response.get("response", {}) if isinstance(response, dict) else {}

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
        attestation_certificates_details,
    ) = simple_module.extract_attestation_details(response)

    client_data_json_b64 = credential_response.get("clientDataJSON")
    client_data_json = client_data_json_b64
    if parsed_client_data_json:
        client_data_json = parsed_client_data_json

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get("clientExtensionResults", {}) if isinstance(response, dict) else {})
    )

    min_pin_length_value = simple_module.extract_min_pin_length(client_extension_results)

    if isinstance(response, dict):
        state_from_request = response.pop("__session_state", None)
    else:
        state_from_request = None

    rp_id = simple_module.session.get("register_rp_id")
    state = simple_module.session.get("state")
    if state is None and isinstance(state_from_request, Mapping):
        state = state_from_request
    if state is None:
        return (
            simple_module.jsonify(
                {
                    "error": "Registration state not found or has expired. Please restart the registration process."
                }
            ),
            400,
        )

    public_key_options_for_checks = simple_module.session.pop("simple_register_public_key", None)
    resolved_rp_id = rp_id or simple_module.determine_rp_id()
    server = simple_module.create_fido_server(rp_id=resolved_rp_id)

    try:
        auth_data = server.register_complete(state, response)
    except Exception as exc:
        simple_module.session.pop("state", None)
        simple_module.session.pop("register_rp_id", None)
        return simple_module.jsonify({"error": str(exc)}), 400

    simple_module.session.pop("state", None)

    authenticator_attachment_response = simple_module.normalize_attachment(
        response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
    )

    raw_attestation_object_b64 = credential_response.get("attestationObject")
    raw_attestation_object = raw_attestation_object_b64

    expected_origin = simple_module.request.headers.get("Origin") or simple_module.request.host_url.rstrip("/")

    attestation_checks = simple_module.perform_attestation_checks(
        response if isinstance(response, Mapping) else {},
        state if isinstance(state, Mapping) else None,
        public_key_options_for_checks if isinstance(public_key_options_for_checks, Mapping) else None,
        auth_data,
        expected_origin,
        resolved_rp_id,
    )

    ctx: Dict[str, Any] = {
        "uname": uname,
        "response": response,
        "credential_response": credential_response,
        "attestation_format": attestation_format,
        "attestation_statement": attestation_statement,
        "parsed_attestation_object": parsed_attestation_object,
        "attestation_certificate_details": attestation_certificate_details,
        "attestation_certificates_details": attestation_certificates_details,
        "client_data_json_b64": client_data_json_b64,
        "client_data_json": client_data_json,
        "client_extension_results": client_extension_results,
        "min_pin_length_value": min_pin_length_value,
        "auth_data": auth_data,
        "authenticator_attachment_response": authenticator_attachment_response,
        "raw_attestation_object_b64": raw_attestation_object_b64,
        "raw_attestation_object": raw_attestation_object,
        "resolved_rp_id": resolved_rp_id,
        "attestation_signature_valid": attestation_checks.get("signature_valid"),
        "attestation_root_valid": attestation_checks.get("root_valid"),
        "attestation_rp_id_hash_valid": attestation_checks.get("rp_id_hash_valid"),
        "attestation_aaguid_match": attestation_checks.get("aaguid_match"),
        "attestation_checks_safe": simple_module.make_json_safe(attestation_checks),
    }

    initialize_registration_context_impl(simple_module, ctx)
    populate_authenticator_data_context_impl(simple_module, ctx)
    populate_rp_debug_context_impl(simple_module, ctx)

    simple_module.session.pop("register_rp_id", None)

    build_stored_credential_context_impl(simple_module, ctx)

    persist_response = persist_registration_context_impl(simple_module, ctx)
    if persist_response is not None:
        return persist_response

    response_payload = build_register_complete_response_payload_impl(simple_module, ctx)
    return simple_module.jsonify(response_payload)
