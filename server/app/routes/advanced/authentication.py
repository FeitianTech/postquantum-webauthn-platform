from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from flask import jsonify, request, session

from ... import config
from ...attachments import (
    attachment_hint_violation,
    normalize_attachment,
    resolve_allowed_attachments,
    resolve_effective_attachments,
)
from ...challenge_registry import consume_ceremony_state, stamp_ceremony_state
from ...encoding import encode_base64url
from ...webauthn import attestation
from .. import binary_helpers
from . import (
    algorithms,
    assertion_credentials,
    assertion_options,
    assertion_verification,
    binary,
    constants,
    parsing,
)

logger = logging.getLogger(__name__)


def _hints(public_key: Mapping[str, Any]) -> list[str]:
    raw_hints = public_key.get("hints")
    if isinstance(raw_hints, list):
        return [item for item in raw_hints if isinstance(item, str)]
    return []


def advanced_authenticate_begin():
    data = request.get_json(silent=True)

    if not data or not data.get("publicKey"):
        return jsonify(
            {"error": "Invalid request: Missing publicKey in CredentialRequestOptions"},
        ), 400

    public_key = data["publicKey"]

    if not public_key.get("challenge"):
        return jsonify({"error": "Missing required field: challenge"}), 400

    allowed_attachment_values = resolve_effective_attachments(_hints(public_key), None)
    session["advanced_authenticate_allowed_attachments"] = list(allowed_attachment_values)

    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = binary._decode_request_binary(challenge_value)
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid challenge format: {exc}"}), 400

    temp_server, resolved_rp_id, stored_rp_name = assertion_options.assertion_server(public_key)
    uv_req = assertion_options.user_verification_requirement(public_key)

    raw_credentials_input = assertion_credentials.credential_list_input(data) or []
    stored_records, serialized_credentials = parsing._parse_client_supplied_credentials(raw_credentials_input)
    if not stored_records:
        return jsonify(
            {"error": "No credentials detected. Please register a credential first."},
        ), 404

    credentials_for_begin, resident_records, resident_key_only = assertion_credentials.select_begin_credentials(
        stored_records, public_key, allowed_attachment_values
    )
    selection_error = assertion_credentials.begin_selection_error(
        credentials_for_begin, resident_records, resident_key_only, allowed_attachment_values
    )
    if selection_error is not None:
        return selection_error

    algorithm_source: Iterable[Any]
    if credentials_for_begin:
        algorithm_source = credentials_for_begin
    else:
        algorithm_source = [record["data"] for record in stored_records if record.get("data") is not None]

    derived_algorithms = algorithms._derive_algorithms_from_credentials(algorithm_source)
    if derived_algorithms:
        temp_server.allowed_algorithms = derived_algorithms

    processed_extensions = assertion_options.process_assertion_extensions(public_key.get("extensions", {}))

    credentials_argument: list[Any] | None = credentials_for_begin if credentials_for_begin else None
    options, state = temp_server.authenticate_begin(
        credentials_argument,
        user_verification=uv_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )

    # Stamped so /complete can tell a fresh state from one replayed out of an
    # old cookie. The copy echoed to the request editor is left unstamped.
    session["advanced_auth_state"] = stamp_ceremony_state(dict(state))
    session["advanced_auth_rp"] = {"id": resolved_rp_id, "name": stored_rp_name}
    session["advanced_auth_credentials_meta"] = {
        "count": len(serialized_credentials),
        "resident_count": sum(1 for entry in serialized_credentials if entry.get("resident")),
    }

    options_payload = dict(options)
    options_payload["__session_state"] = attestation.make_json_safe(state)
    public_key_dict = options_payload.get("publicKey")
    if isinstance(public_key_dict, Mapping):
        allow_list = public_key_dict.get("allowCredentials")
        if resident_key_only or allow_list is None:
            public_key_dict.pop("allowCredentials", None)

    return jsonify(attestation.make_json_safe(options_payload))


def advanced_authenticate_complete():
    data = request.get_json(silent=True) or {}

    # Consumed before anything can fail, as in the simple flow: an early error
    # burns the challenge too, so a replay is always labelled as one. The
    # request editor is permissive, so a replayed or stale server challenge is
    # reported via ``challengeStatus`` rather than rejected -- on every response.
    state = session.pop("advanced_auth_state", None)
    if state is not None:
        trace = {
            "challengeSource": constants.CHALLENGE_SOURCE_SERVER,
            "challengeStatus": consume_ceremony_state(state),
        }
    else:
        trace = {
            "challengeSource": constants.CHALLENGE_SOURCE_CLIENT,
            "challengeStatus": constants.CHALLENGE_STATUS_NOT_TRACKED,
        }

    def _fail(payload: dict[str, Any], status: int = 400):
        payload.setdefault("challengeSource", trace["challengeSource"])
        payload.setdefault("challengeStatus", trace["challengeStatus"])
        return jsonify(payload), status

    response = data.get("__assertion_response")
    if not response:
        return _fail({"error": "Assertion response is required"})

    original_request = {key: value for key, value in data.items() if not key.startswith("__")}

    public_key = original_request.get("publicKey")
    if not isinstance(public_key, Mapping):
        return _fail({"error": "Invalid request: Missing publicKey in JSON editor content"})

    raw_allow_credentials = public_key.get("allowCredentials")
    resident_key_only = not (list(raw_allow_credentials) if isinstance(raw_allow_credentials, list) else [])

    allowed_attachments = resolve_allowed_attachments(
        session.pop("advanced_authenticate_allowed_attachments", None),
        resolve_effective_attachments(_hints(public_key), None),
    )
    violation = attachment_hint_violation(
        allowed_attachments,
        normalize_attachment(response.get("authenticatorAttachment") if isinstance(response, Mapping) else None),
    )
    if violation is not None:
        return _fail({"error": violation})

    stored_records, restore_failure = assertion_credentials.restore_complete_credentials(data)
    if restore_failure is not None:
        return _fail(*restore_failure)

    lookup = assertion_credentials.credential_lookup(stored_records)
    all_credentials = [record["data"] for record in stored_records if record.get("data") is not None]

    response_mapping: Mapping[str, Any] = response if isinstance(response, Mapping) else {}
    credential_id_bytes = binary_helpers.extract_assertion_credential_id(response_mapping)
    selected_record = lookup.get(credential_id_bytes) if credential_id_bytes else None

    non_discoverable = assertion_credentials.non_discoverable_error(
        resident_key_only, selected_record, credential_id_bytes
    )
    if non_discoverable is not None:
        return _fail(non_discoverable)

    state, refusal = _state_and_origin(data, state, response, trace)
    if refusal is not None:
        return refusal

    try:
        return assertion_verification.verify_assertion(
            data=data,
            state=state,
            public_key=public_key,
            response=response,
            all_credentials=all_credentials,
            lookup=lookup,
            credential_id_bytes=credential_id_bytes,
            selected_record=selected_record,
            trace=trace,
        )
    except Exception as exc:
        response_payload: dict[str, Any] = {"error": str(exc), **trace}
        failed_credential_id = credential_id_bytes
        if not failed_credential_id and isinstance(response, Mapping):
            failed_credential_id = binary_helpers.extract_assertion_credential_id(response)
        if failed_credential_id:
            response_payload["failedCredentialId"] = (
                encode_base64url(failed_credential_id)
            )
        return jsonify(response_payload), 400


def _state_and_origin(data: Mapping[str, Any], state: Any, response: Any, trace: Mapping[str, Any]) -> tuple[Any, Any]:
    """The ceremony state (the session's, else the request's), or the 400 for none or a bad origin."""

    if state is None:
        fallback_state = data.get("__session_state")
        if isinstance(fallback_state, Mapping):
            state = fallback_state
    if state is None:
        session.pop("advanced_auth_rp", None)
        return None, (
            jsonify(
                {
                    "error": (
                        "Authentication state not found or has expired. "
                        "Please restart the authentication flow."
                    ),
                    **trace,
                }
            ),
            400,
        )

    ceremony_origin = config.extract_client_data_origin(
        response.get("response") if isinstance(response, Mapping) else None
    )
    if not config.is_origin_allowed(ceremony_origin):
        session.pop("advanced_auth_rp", None)
        return None, (
            jsonify(
                {
                    "error": (
                        "Ceremony origin is not permitted by the configured "
                        "FIDO_SERVER_ALLOWED_ORIGINS allowlist."
                    ),
                    **trace,
                }
            ),
            400,
        )
    return state, None
