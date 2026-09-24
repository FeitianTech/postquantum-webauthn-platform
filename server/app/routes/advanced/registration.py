from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from flask import jsonify, request, session

from fido2.webauthn import PublicKeyCredentialUserEntity

from ...challenge_registry import consume_ceremony_state, stamp_ceremony_state
from ...webauthn import attestation
from . import (
    algorithms,
    constants,
    registration_attestation,
    registration_inputs,
    registration_options,
    registration_persistence,
    registration_record,
)

logger = logging.getLogger(__name__)


def advanced_register_complete():
    data = request.get_json(silent=True) or {}
    # Consumed before anything can fail, as in the simple flow: an early error
    # burns the challenge too, so a replay is always labelled as one. The
    # request editor is permissive: it reports ``challengeStatus``, it does not
    # reject on it. Every response carries the trace.
    session_state = session.pop("advanced_state", None)
    state_trace: dict[str, Any] = {
        "challengeSource": constants.CHALLENGE_SOURCE_SERVER if session_state is not None else constants.CHALLENGE_SOURCE_CLIENT,
        "challengeStatus": (
            consume_ceremony_state(session_state) if session_state is not None else constants.CHALLENGE_STATUS_NOT_TRACKED
        ),
    }
    return _with_challenge_source(_register_complete(data, session_state, state_trace), state_trace)


def _register_complete(data: Mapping[str, Any], session_state: Any, state_trace: dict[str, Any]) -> Any:
    prepared, error_response = registration_inputs.prepare_register_complete_inputs(data)
    if error_response is not None:
        return error_response

    response = prepared["response"]
    try:
        state_ctx, state_error = registration_inputs.resolve_state_and_registration_server(
            data=data,
            original_request=prepared["originalRequest"],
            public_key=prepared["publicKey"],
            response=response if isinstance(response, Mapping) else {},
            attestation_format=prepared["attestationFormat"],
            attestation_statement=prepared["attestationStatement"],
            raw_attestation_object=prepared["rawAttestationObject"],
            trace=state_trace,
            session_state=session_state,
        )
        if state_error is not None:
            return _with_challenge_source(state_error, state_trace)
        return _record_verified_registration(prepared, state_ctx, state_trace)
    except Exception as exc:
        return jsonify(
            {
                "error": str(exc),
                "challengeSource": state_trace["challengeSource"],
            }
        ), 400


def _record_verified_registration(
    prepared: Mapping[str, Any], state_ctx: Mapping[str, Any], state_trace: Mapping[str, Any]
) -> Any:
    """What follows fido2 accepting a registration: checks, record, artifact, answer."""

    response = prepared["response"]
    public_key = prepared["publicKey"]
    auth_data = state_ctx["authData"]

    attestation_checks, origin_error = registration_attestation.check_origin_and_attestation(
        response=response,
        state_ctx=state_ctx,
        public_key=public_key,
        challenge_source=state_trace["challengeSource"],
    )
    if origin_error is not None:
        return origin_error

    analysis = registration_attestation.summarise_attestation(attestation_checks)
    extensions_summary = registration_attestation.authenticator_extensions_summary(auth_data)
    user_handle = registration_record.resolve_user_handle(prepared["userInfo"], prepared["username"])
    credential_info = registration_record.build_credential_info(
        prepared=prepared,
        auth_data=auth_data,
        analysis=analysis,
        user_handle=user_handle,
        extensions_summary=extensions_summary,
    )
    algo, algoname = registration_record.resolve_algorithm(credential_info, auth_data)
    debug_info = registration_record.build_debug_info(
        public_key=public_key,
        attestation_format=prepared["attestationFormat"],
        auth_data=auth_data,
        analysis=analysis,
        algo=algo,
        challenge_source=state_trace["challengeSource"],
    )

    material = registration_record.build_registration_material(
        auth_data=auth_data,
        attestation_format=prepared["attestationFormat"],
        attestation_statement=prepared["attestationStatement"],
        attestation_certificate_details=prepared["attestationCertificateDetails"],
        attestation_certificates_details=prepared["attestationCertificatesDetails"],
        client_extension_results=prepared["clientExtensionResults"],
        credential_info=credential_info,
        response=response,
        user_handle=user_handle,
        resolved_rp_id=state_ctx["resolvedRpId"],
        resident_key_required=bool(prepared["residentKeyRequired"]),
        attestation_rp_id_hash_valid=analysis["rpIdHashValid"],
        attestation_checks_safe=analysis["checksSafe"],
        attestation_summary=analysis["summary"],
    )

    if extensions_summary:
        material["rpInfo"]["registrationData"]["authenticatorExtensions"] = attestation.make_json_safe(
            extensions_summary
        )

    return registration_persistence.finalize_registration_completion(
        stored_credential=material["storedCredential"],
        rp_info=material["rpInfo"],
        metadata_summary=analysis["metadataSummary"],
        response=response,
        metadata_session_id=prepared["metadataSessionId"],
        username=prepared["username"],
        warnings=analysis["warnings"],
        debug_info=debug_info,
        algoname=algoname,
        resolved_rp_id=state_ctx["resolvedRpId"],
        credential_id_bytes=material["credentialIdBytes"],
        aaguid_bytes=material.get("aaguidBytes"),
        auth_data=auth_data,
        attestation_format=prepared["attestationFormat"],
        attestation_object_b64=prepared["attestationObjectB64"],
        client_data_json_b64=prepared["clientDataJsonB64"],
        user_handle=user_handle,
        display_name=prepared["displayName"],
    )


def _with_challenge_source(
    error_response: Any,
    state_trace: Mapping[str, Any],
) -> Any:
    """Re-emit a response with the challenge source and status attached."""

    payload, status = error_response if isinstance(error_response, tuple) else (error_response, 200)
    try:
        body = payload.get_json(silent=True) or {}
    except Exception:
        return error_response
    if not isinstance(body, Mapping):
        return error_response
    merged = dict(body)
    for key, value in state_trace.items():
        merged.setdefault(key, value)
    return jsonify(merged), status


def advanced_register_begin():
    data = request.get_json(silent=True)
    begin_request, error_response = registration_options.parse_begin_request(data)
    if error_response is not None:
        return error_response
    public_key = begin_request.public_key

    warnings: list[str] = []
    temp_server, rp_entity = registration_options.registration_server(public_key)

    algorithms.configure_allowed_algorithms(public_key, temp_server, warnings)
    public_key["pubKeyCredParams"] = algorithms.advertised_algorithm_params(temp_server)

    logger.info(
        "Advanced registration request will advertise algorithms: %s",
        [entry.get("alg") for entry in public_key["pubKeyCredParams"]],
    )

    selection = registration_options.authenticator_selection(public_key)
    session["advanced_register_allowed_attachments"] = list(selection.allowed_attachments)

    user_entity = PublicKeyCredentialUserEntity(
        id=begin_request.user_id,
        name=begin_request.username,
        display_name=begin_request.display_name,
    )

    exclude_list = registration_options.build_exclude_list(public_key)
    processed_extensions = registration_options.build_processed_extensions(public_key)

    options, state = temp_server.register_begin(
        user_entity,
        exclude_list,
        user_verification=selection.user_verification,
        authenticator_attachment=selection.attachment,
        resident_key_requirement=selection.resident_key,
        challenge=begin_request.challenge,
        extensions=processed_extensions if processed_extensions else None,
    )

    # Stamped so /complete can tell a fresh challenge from a replayed or stale one.
    session["advanced_state"] = stamp_ceremony_state(dict(state))
    session["advanced_rp"] = {"id": rp_entity.id, "name": rp_entity.name}
    session["advanced_original_request"] = data

    response_payload = dict(options)
    response_payload["__session_state"] = attestation.make_json_safe(state)
    if warnings:
        response_payload["warnings"] = warnings

    return jsonify(attestation.make_json_safe(response_payload))
