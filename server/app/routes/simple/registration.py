from __future__ import annotations

import copy
import logging
from collections.abc import Mapping, MutableMapping
from typing import Any

from fido2.cose import CoseKey
from fido2.webauthn import (
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
)
from flask import jsonify, request, session

from ... import json_values
from ...attachments import normalize_attachment
from ...challenge_registry import (
    CHALLENGE_FRESH,
    CHALLENGE_REPLAYED,
    consume_ceremony_state,
    stamp_ceremony_state,
)
from ...config import origins, relying_party
from ...webauthn.attestation import aaguid as attestation_aaguid
from ...webauthn.attestation import certificates as attestation_certificates
from ...webauthn.attestation import checks
from . import parsing, registration_persistence, registration_record

logger = logging.getLogger(__name__)


def _complete_inputs(response: Any, credential_response: Mapping[str, Any]) -> dict[str, Any]:
    """The attestation, client data and extension outputs the registration response carries."""

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
        attestation_certificates_details,
    ) = attestation_certificates.extract_attestation_details(response)

    client_data_json_b64 = credential_response.get("clientDataJSON")
    client_data_json = client_data_json_b64
    if parsed_client_data_json:
        client_data_json = parsed_client_data_json

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get("clientExtensionResults", {}) if isinstance(response, dict) else {})
    )

    return {
        "attestation_format": attestation_format,
        "attestation_statement": attestation_statement,
        "parsed_attestation_object": parsed_attestation_object,
        "attestation_certificate_details": attestation_certificate_details,
        "attestation_certificates_details": attestation_certificates_details,
        "client_data_json": client_data_json,
        "client_extension_results": client_extension_results,
        "min_pin_length_value": attestation_aaguid.extract_min_pin_length(client_extension_results),
    }


def _consume_registration_state() -> tuple[Any, Any]:
    """The session's ceremony state, consumed; or the 400 when it is missing, replayed or stale."""

    # Popping the state is not enough on its own: the session is a client-side
    # cookie, so an earlier copy that still holds this state can be resent.
    # Consuming the challenge server-side is what makes it single-use.
    state = session.pop("state", None)
    if state is None:
        # Drop any stale ceremony leftovers so the next attempt starts clean.
        session.pop("register_rp_id", None)
        session.pop("simple_register_public_key", None)
        return None, (
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
        return None, (jsonify({"error": message}), 400)
    return state, None


def _verify_registration(
    state: Any, response: Any, credential_response: Mapping[str, Any], rp_id: Any
) -> tuple[dict[str, Any] | None, Any]:
    """fido2's verification, the origin allowlist and the attestation checks; or the 400."""

    public_key_options_for_checks = session.pop("simple_register_public_key", None)
    resolved_rp_id = rp_id or relying_party.determine_rp_id()
    server = relying_party.create_fido_server(rp_id=resolved_rp_id)

    try:
        auth_data = server.register_complete(state, response)
    except Exception as exc:
        session.pop("register_rp_id", None)
        return None, (jsonify({"error": str(exc)}), 400)

    # fido2 checked the origin against the RP ID and the allowlist. It is read from
    # clientDataJSON -- NOT from the request's own Origin header, which the caller
    # also controls.
    ceremony_origin = origins.extract_client_data_origin(credential_response)

    # determine_expected_origin only echoes a candidate that is itself
    # allowlisted, so this can never become a self-referential comparison.
    expected_origin = origins.determine_expected_origin(ceremony_origin) or (
        request.host_url.rstrip("/")
    )

    attestation_checks = checks.perform_attestation_checks(
        response if isinstance(response, Mapping) else {},
        state if isinstance(state, Mapping) else None,
        public_key_options_for_checks if isinstance(public_key_options_for_checks, Mapping) else None,
        auth_data,
        expected_origin,
        resolved_rp_id,
    )
    return {"auth_data": auth_data, "resolved_rp_id": resolved_rp_id, "attestation_checks": attestation_checks}, None


def _registration_context(
    uname: Any, response: Any, credential_response: Mapping[str, Any], inputs: Mapping[str, Any], verified: Mapping[str, Any]
) -> dict[str, Any]:
    attestation_checks = verified["attestation_checks"]
    raw_attestation_object_b64 = credential_response.get("attestationObject")
    return {
        "uname": uname,
        "response": response,
        "credential_response": credential_response,
        **inputs,
        "auth_data": verified["auth_data"],
        "authenticator_attachment_response": normalize_attachment(
            response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
        ),
        "raw_attestation_object_b64": raw_attestation_object_b64,
        "raw_attestation_object": raw_attestation_object_b64,
        "resolved_rp_id": verified["resolved_rp_id"],
        "attestation_signature_valid": attestation_checks.get("signature_valid"),
        "attestation_root_valid": attestation_checks.get("root_valid"),
        "attestation_rp_id_hash_valid": attestation_checks.get("rp_id_hash_valid"),
        "attestation_aaguid_match": attestation_checks.get("aaguid_match"),
        "attestation_checks_safe": json_values.make_json_safe(attestation_checks),
    }


def _attestation_error_response(attestation_checks: Mapping[str, Any]) -> Any:
    """The 400 when the attestation checks found errors: the simple flow rejects on them."""

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
    return None


def register_complete():
    uname = request.args.get("email")
    response = request.get_json(silent=True) or {}
    credential_response = response.get("response", {}) if isinstance(response, dict) else {}
    inputs = _complete_inputs(response, credential_response)

    # A client-supplied ``__session_state`` is stripped and ignored: accepting
    # it would let the caller choose the challenge it is verified against.
    if isinstance(response, dict):
        response.pop("__session_state", None)

    rp_id = session.get("register_rp_id")
    state, error_response = _consume_registration_state()
    if error_response is not None:
        return error_response

    verified, error_response = _verify_registration(state, response, credential_response, rp_id)
    if error_response is not None:
        return error_response

    ctx = _registration_context(uname, response, credential_response, inputs, verified)
    error_response = _attestation_error_response(verified["attestation_checks"])
    if error_response is not None:
        return error_response

    registration_record.initialize_registration_context(ctx)
    registration_record.populate_authenticator_data_context(ctx)
    registration_record.populate_rp_debug_context(ctx)

    session.pop("register_rp_id", None)

    registration_record.build_stored_credential_context(ctx)

    persist_response = registration_persistence.persist_registration_context(ctx)
    if persist_response is not None:
        return persist_response

    return jsonify(registration_record.build_register_complete_response_payload(ctx))


_SIMPLE_ALLOWED_ALGORITHMS: tuple[int, ...] = tuple(
    alg
    for alg in (-50, -49, -48, -8, -7, -257, -35)
    if alg in set(CoseKey.supported_algorithms())
)

# The request's algorithms as begin keeps them in the session, which complete
# checks the new credential's algorithm against: every one this server verifies,
# ML-DSA first. The browser is offered _SIMPLE_ALLOWED_ALGORITHMS instead.
_SIMPLE_REQUEST_ALGORITHMS: tuple[int, ...] = (
    -48, -49, -50, -7, -9, -8, -19, -53, -35, -36, -51, -52, -47, -37, -38, -39, -257, -258, -259, -65535,
)

def register_begin():
    payload = request.get_json(silent=True) or {}

    existing_credentials_raw: list[Any] = []
    if isinstance(payload, Mapping):
        raw_candidates = payload.get("credentials") or payload.get("existingCredentials")
        if isinstance(raw_candidates, list):
            existing_credentials_raw = raw_candidates

    credentials, serialized = parsing._parse_client_credentials(existing_credentials_raw)
    if serialized:
        session["simple_credentials"] = serialized
    else:
        session.pop("simple_credentials", None)

    rp_id = relying_party.determine_rp_id()
    server = relying_party.create_fido_server(rp_id=rp_id)
    server.allowed_algorithms = [
        PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=alg)
        for alg in _SIMPLE_REQUEST_ALGORITHMS
    ]

    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(
            id=b"user_id",
            name="a_user",
            display_name="A. User",
        ),
        credentials,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    # Stamped so /complete can refuse a stale state replayed from an old cookie.
    session["state"] = stamp_ceremony_state(dict(state))
    session["register_rp_id"] = rp_id

    options_dict = dict(options)
    # The ceremony state (and therefore the challenge) is deliberately NOT
    # returned to the client: the simple flow binds the challenge to the
    # server-side session only.
    public_key_options = options_dict.get("publicKey")
    if isinstance(public_key_options, MutableMapping):
        # A copy: the parameters below are filtered in place.
        session["simple_register_public_key"] = copy.deepcopy(public_key_options)
    else:
        session.pop("simple_register_public_key", None)

    if _SIMPLE_ALLOWED_ALGORITHMS:
        public_key_options = options_dict.get("publicKey")
        if isinstance(public_key_options, MutableMapping):
            params = public_key_options.get("pubKeyCredParams")
            allowed_params: list[dict[str, Any]] = []
            existing_param_map: dict[int, dict[str, Any]] = {}
            if isinstance(params, list):
                for param in params:
                    if isinstance(param, MutableMapping):
                        alg_value = param.get("alg")
                        if isinstance(alg_value, int) and alg_value in _SIMPLE_ALLOWED_ALGORITHMS:
                            cloned = dict(param)
                            cloned["type"] = "public-key"
                            existing_param_map[alg_value] = cloned
            for alg in _SIMPLE_ALLOWED_ALGORITHMS:
                if alg in existing_param_map:
                    allowed_params.append(existing_param_map[alg])
                else:
                    allowed_params.append({"type": "public-key", "alg": alg})
            public_key_options["pubKeyCredParams"] = allowed_params

    return jsonify(options_dict)
