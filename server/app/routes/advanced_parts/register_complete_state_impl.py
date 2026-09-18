from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from flask import jsonify, session

from ... import config
from . import logging_helpers_impl

#: The ceremony challenge was taken from the server-side Flask session.
CHALLENGE_SOURCE_SERVER = "server-session"
#: The ceremony challenge was taken from the request body (request-editor mode).
CHALLENGE_SOURCE_CLIENT = "client-supplied"


def resolve_state_and_registration_server(
    advanced_module: Any,
    *,
    data: Mapping[str, Any],
    original_request: Mapping[str, Any],
    public_key: Mapping[str, Any],
    response: Mapping[str, Any],
    attestation_format: Any,
    attestation_statement: Any,
    raw_attestation_object: Any,
    trace: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, Any | None]:
    state = session.pop("advanced_state", None)
    challenge_source = CHALLENGE_SOURCE_SERVER if state is not None else None
    if state is None:
        fallback_state = data.get("__session_state")
        if isinstance(fallback_state, Mapping):
            state = fallback_state
            challenge_source = CHALLENGE_SOURCE_CLIENT

    # Record where the challenge came from before anything below can raise, so
    # that the caller can always report it -- the advanced flow may be
    # permissive, but it must never be silent about it.
    if trace is not None and challenge_source is not None:
        trace["challengeSource"] = challenge_source

    stored_original_request = session.pop("advanced_original_request", None)
    if stored_original_request is None and isinstance(original_request, Mapping):
        stored_original_request = original_request

    if state is None:
        return None, (
            jsonify(
                {
                    "error": (
                        "Registration state not found or has expired. "
                        "Please restart the registration process."
                    )
                }
            ),
            400,
        )

    stored_rp = session.pop("advanced_rp", None)
    stored_rp_id = None
    stored_rp_name = None
    if isinstance(stored_rp, Mapping):
        stored_rp_id = stored_rp.get("id")
        stored_rp_name = stored_rp.get("name")
    elif isinstance(public_key, Mapping):
        rp_candidate = public_key.get("rp")
        if isinstance(rp_candidate, Mapping):
            stored_rp_id = rp_candidate.get("id")
            stored_rp_name = rp_candidate.get("name")
        rp_id_candidate = public_key.get("rpId")
        if stored_rp_id is None and isinstance(rp_id_candidate, str):
            stored_rp_id = rp_id_candidate

    resolved_rp_id = config.determine_rp_id(stored_rp_id)
    register_server = config.create_fido_server(rp_id=resolved_rp_id, rp_name=stored_rp_name)
    auth_data = register_server.register_complete(state, response)

    logging_helpers_impl._log_authenticator_attestation_response_impl(
        attestation_format,
        auth_data,
        attestation_statement,
        raw_attestation_object,
    )

    return {
        "state": state,
        "storedOriginalRequest": stored_original_request,
        "resolvedRpId": resolved_rp_id,
        "authData": auth_data,
        "challengeSource": challenge_source,
    }, None
