from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from flask import jsonify, request, session

from ... import attestation, config
from ...attachments import normalize_attachment
from ...challenge_registry import (
    CHALLENGE_FRESH,
    CHALLENGE_REPLAYED,
    consume_ceremony_state,
)
from . import (
    register_complete_context_authenticator_impl,
    register_complete_context_b_impl,
    register_complete_context_init_impl,
    register_complete_context_rp_debug_impl,
)


def registration():
    uname = request.args.get("email")
    response = request.get_json(silent=True) or {}
    credential_response = response.get("response", {}) if isinstance(response, dict) else {}

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
        attestation_certificates_details,
    ) = attestation.extract_attestation_details(response)

    client_data_json_b64 = credential_response.get("clientDataJSON")
    client_data_json = client_data_json_b64
    if parsed_client_data_json:
        client_data_json = parsed_client_data_json

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get("clientExtensionResults", {}) if isinstance(response, dict) else {})
    )

    min_pin_length_value = attestation.extract_min_pin_length(client_extension_results)

    # A client-supplied ``__session_state`` is stripped and ignored: accepting
    # it would let the caller choose the challenge it is verified against.
    if isinstance(response, dict):
        response.pop("__session_state", None)

    rp_id = session.get("register_rp_id")
    # Popping the state is not enough on its own: the session is a client-side
    # cookie, so an earlier copy that still holds this state can be resent.
    # Consuming the challenge server-side is what makes it single-use.
    state = session.pop("state", None)
    if state is None:
        # Drop any stale ceremony leftovers so the next attempt starts clean.
        session.pop("register_rp_id", None)
        session.pop("simple_register_public_key", None)
        return (
            jsonify(
                {
                    "error": "Registration state not found or has expired. Please restart the registration process."
                }
            ),
            400,
        )

    challenge_verdict = consume_ceremony_state(state)
    if challenge_verdict != CHALLENGE_FRESH:
        session.pop("register_rp_id", None)
        session.pop("simple_register_public_key", None)
        if challenge_verdict == CHALLENGE_REPLAYED:
            message = (
                "This registration challenge has already been used. "
                "Please restart the registration process."
            )
        else:
            message = "Registration challenge has expired. Please restart the registration process."
        return jsonify({"error": message}), 400

    public_key_options_for_checks = session.pop("simple_register_public_key", None)
    resolved_rp_id = rp_id or config.determine_rp_id()
    server = config.create_fido_server(rp_id=resolved_rp_id)

    try:
        auth_data = server.register_complete(state, response)
    except Exception as exc:
        session.pop("register_rp_id", None)
        return jsonify({"error": str(exc)}), 400

    authenticator_attachment_response = normalize_attachment(
        response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
    )

    raw_attestation_object_b64 = credential_response.get("attestationObject")
    raw_attestation_object = raw_attestation_object_b64

    # The origin the ceremony claims, read from clientDataJSON -- NOT from the
    # request's own Origin header, which the caller also controls.
    ceremony_origin = config.extract_client_data_origin(credential_response)
    if not config.is_origin_allowed(ceremony_origin):
        session.pop("register_rp_id", None)
        return (
            jsonify(
                {
                    "error": (
                        "Ceremony origin is not permitted by the configured "
                        "FIDO_SERVER_ALLOWED_ORIGINS allowlist."
                    )
                }
            ),
            400,
        )

    # determine_expected_origin only echoes a candidate that is itself
    # allowlisted, so this can never become a self-referential comparison.
    expected_origin = config.determine_expected_origin(ceremony_origin) or (
        request.host_url.rstrip("/")
    )

    attestation_checks = attestation.perform_attestation_checks(
        response if isinstance(response, Mapping) else {},
        state if isinstance(state, Mapping) else None,
        public_key_options_for_checks if isinstance(public_key_options_for_checks, Mapping) else None,
        auth_data,
        expected_origin,
        resolved_rp_id,
    )

    ctx: dict[str, Any] = {
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
        "attestation_checks_safe": attestation.make_json_safe(attestation_checks),
    }

    attestation_errors = attestation_checks.get("errors")
    if isinstance(attestation_errors, list) and attestation_errors:
        session.pop("register_rp_id", None)
        return (
            jsonify(
                {
                    "error": "Registration verification failed.",
                    "verified": False,
                    "attestationErrors": [
                        str(message) for message in attestation_errors
                    ],
                }
            ),
            400,
        )

    register_complete_context_init_impl.initialize_registration_context_impl(ctx)
    register_complete_context_authenticator_impl.populate_authenticator_data_context_impl(ctx)
    register_complete_context_rp_debug_impl.populate_rp_debug_context_impl(ctx)

    session.pop("register_rp_id", None)

    register_complete_context_b_impl.build_stored_credential_context_impl(ctx)

    persist_response = register_complete_context_b_impl.persist_registration_context_impl(ctx)
    if persist_response is not None:
        return persist_response

    response_payload = register_complete_context_b_impl.build_register_complete_response_payload_impl(ctx)
    return jsonify(response_payload)
