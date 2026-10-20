from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from fido2.cose import CoseKey
from fido2.webauthn import (
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
)
from flask import Blueprint, jsonify, request, session

from ... import json_values, visitor_session
from ...challenge_registry import (
    CHALLENGE_FRESH,
    CHALLENGE_REPLAYED,
    consume_ceremony_state,
    stamp_ceremony_state,
)
from ...config import origins, relying_party
from ...mds import provisioning as mds_provisioning
from ...webauthn.attachments import normalize_attachment
from ...webauthn.attestation import aaguid as attestation_aaguid
from ...webauthn.attestation import certificates as attestation_certificates
from ...webauthn.attestation import checks, error_codes, request_expectations
from .. import ceremony_session, json_body
from . import (
    account,
    parsing,
    registration_persistence,
    registration_record,
    registration_request,
)

bp = Blueprint("simple_registration", __name__)

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


def _drop_begun_registration() -> None:
    """Drop what begin kept beside the ceremony's state, so the next attempt starts clean."""

    for key in ("register_rp_id", "simple_register_public_key", "simple_register_user", "simple_register_excluded"):
        session.pop(key, None)


def _consume_registration_state() -> tuple[Any, Any]:
    """The session's ceremony state, consumed; or the 400 when it is missing, replayed or stale."""

    # Popping the state is not enough on its own: the session is a client-side
    # cookie, so an earlier copy that still holds this state can be resent.
    # Consuming the challenge server-side is what makes it single-use.
    state = session.pop("simple_register_state", None)
    if state is None:
        _drop_begun_registration()
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
        _drop_begun_registration()
        if challenge_verdict == CHALLENGE_REPLAYED:
            message = (
                "This registration challenge has already been used. "
                "Please restart the registration process."
            )
        else:
            message = "Registration challenge has expired. Please restart the registration process."
        return None, (jsonify({"error": message}), 400)
    return state, None


def _begun_user() -> tuple[Mapping[str, Any] | None, Any]:
    """The account begin issued the options for, its user handle and username; or the
    400 when complete's username is another."""

    begun = session.pop("simple_register_user", None)
    username = begun.get("name") if isinstance(begun, Mapping) else None
    if username is None or username != account.read_username(request.args.get("email"))[0]:
        _drop_begun_registration()
        return None, (
            jsonify({"error": "This registration began for another username. Please restart the registration process."}),
            400,
        )
    return begun, None


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

    # Only an integrity error refuses the registration; every other finding is its warning.
    attestation_checks = error_codes.integrity_errors_only(
        checks.perform_attestation_checks(
            response if isinstance(response, Mapping) else {},
            state if isinstance(state, Mapping) else None,
            public_key_options_for_checks if isinstance(public_key_options_for_checks, Mapping) else None,
            auth_data,
            expected_origin,
            resolved_rp_id,
        )
    )
    return {"auth_data": auth_data, "resolved_rp_id": resolved_rp_id, "attestation_checks": attestation_checks}, None


def _registration_context(
    user: Mapping[str, Any],
    excluded: int,
    response: Any,
    credential_response: Mapping[str, Any],
    inputs: Mapping[str, Any],
    verified: Mapping[str, Any],
) -> registration_record.SimpleRegistration:
    attestation_checks = verified["attestation_checks"]
    return registration_record.SimpleRegistration(
        uname=user["name"],
        user_id=user["id"],
        exclude_credentials_count=excluded,
        response=response,
        **inputs,
        auth_data=verified["auth_data"],
        authenticator_attachment_response=normalize_attachment(
            response.get("authenticatorAttachment") if isinstance(response, Mapping) else None
        ),
        raw_attestation_object_b64=credential_response.get("attestationObject"),
        resolved_rp_id=verified["resolved_rp_id"],
        attestation_signature_valid=attestation_checks.get("signature_valid"),
        attestation_root_valid=attestation_checks.get("root_valid"),
        attestation_rp_id_hash_valid=attestation_checks.get("rp_id_hash_valid"),
        attestation_aaguid_match=attestation_checks.get("aaguid_match"),
        attestation_checks_safe=json_values.make_json_safe(attestation_checks),
    )


def _attestation_error_response(attestation_checks: Mapping[str, Any]) -> Any:
    """The 400 when the attestation checks found an integrity error, the only errors the simple flow keeps."""

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


@bp.route("/api/register/complete", methods=["POST"])
@mds_provisioning.waits_for_the_snapshot
def register_complete():
    response = json_body.json_object()
    inner_response = response.get("response")
    credential_response = inner_response if isinstance(inner_response, Mapping) else {}

    # A client-supplied ``__session_state`` is stripped and ignored: accepting
    # it would let the caller choose the challenge it is verified against.
    if isinstance(response, dict):
        response.pop("__session_state", None)

    rp_id = session.get("register_rp_id")
    state, error_response = _consume_registration_state()
    if error_response is not None:
        return error_response

    # Refused before fido2 runs: once it has accepted, nothing about the name may fail.
    user, error_response = _begun_user()
    if error_response is not None:
        return error_response
    excluded = session.pop("simple_register_excluded", 0)

    verified, error_response = _verify_registration(state, response, credential_response, rp_id)
    if error_response is not None:
        return error_response

    # Read only now: the attestation's certificates are parsed for a ceremony fido2 accepted.
    inputs = _complete_inputs(response, credential_response)
    reg = _registration_context(user, excluded, response, credential_response, inputs, verified)
    error_response = _attestation_error_response(verified["attestation_checks"])
    if error_response is not None:
        return error_response

    registration_record.initialize_registration_context(reg)
    registration_record.populate_authenticator_data_context(reg)
    registration_record.populate_rp_debug_context(reg)

    session.pop("register_rp_id", None)

    registration_record.build_stored_credential_context(reg)

    persist_response = registration_persistence.persist_registration_context(reg)
    if persist_response is not None:
        return persist_response

    return jsonify(registration_record.build_register_complete_response_payload(reg))


# The algorithms the browser is offered, ML-DSA first, of those this server
# verifies. Begin keeps them in the session, and complete's checks hold the new
# credential's algorithm to them.
_SIMPLE_ALLOWED_ALGORITHMS: tuple[int, ...] = tuple(
    alg
    for alg in (-50, -49, -48, -8, -7, -257, -35)
    if alg in set(CoseKey.supported_algorithms())
)


@bp.route("/api/register/begin", methods=["POST"])
@ceremony_session.ceremony_begin
def register_begin():
    username, refusal = account.read_username(request.args.get("email"))
    if refusal is not None:
        return jsonify({"error": refusal}), 400
    payload = json_body.json_object()

    existing_credentials_raw: list[Any] = []
    if isinstance(payload, Mapping):
        raw_candidates = payload.get("credentials") or payload.get("existingCredentials")
        if isinstance(raw_candidates, list):
            existing_credentials_raw = raw_candidates

    credentials, _serialized = parsing._parse_client_credentials(existing_credentials_raw)

    # The account lives in the visitor's namespace, minted here when they have
    # none: its user handle is bound to it.
    user_id = account.user_handle(visitor_session.ensure_id(), username)

    rp_id = relying_party.determine_rp_id()
    server = relying_party.create_fido_server(rp_id=rp_id)
    server.allowed_algorithms = [
        PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=alg)
        for alg in _SIMPLE_ALLOWED_ALGORITHMS
    ]

    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(id=user_id, name=username, display_name=username),
        credentials,
        resident_key_requirement=registration_request.RESIDENT_KEY,
        user_verification=registration_request.USER_VERIFICATION,
        authenticator_attachment=registration_request.AUTHENTICATOR_ATTACHMENT,
        extensions=dict(registration_request.EXTENSIONS),
    )

    # Stamped so /complete can refuse a stale state replayed from an old cookie.
    session["simple_register_state"] = stamp_ceremony_state(dict(state))
    session["register_rp_id"] = rp_id
    session["simple_register_user"] = {"id": user_id, "name": username}

    options_dict = dict(options)
    # The ceremony state (and therefore the challenge) is deliberately NOT
    # returned to the client: the simple flow binds the challenge to the
    # server-side session only. fido2 gives publicKey as a dict.
    public_key_options = options_dict["publicKey"]
    # What complete's attestation checks read of the options, and nothing else of
    # them: an exclude list would not fit a cookie.
    session["simple_register_public_key"] = {
        name: public_key_options[name]
        for name in request_expectations.CHECKED_REQUEST_MEMBERS
        if name in public_key_options
    }
    # Their number only: the record says how many were excluded.
    session["simple_register_excluded"] = len(public_key_options.get("excludeCredentials") or [])

    return jsonify(options_dict)
