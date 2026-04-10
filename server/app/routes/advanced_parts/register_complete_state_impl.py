from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple


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
) -> Tuple[Optional[Dict[str, Any]], Optional[Any]]:
    state = advanced_module.session.pop("advanced_state", None)
    if state is None:
        fallback_state = data.get("__session_state")
        if isinstance(fallback_state, Mapping):
            state = fallback_state

    stored_original_request = advanced_module.session.pop("advanced_original_request", None)
    if stored_original_request is None and isinstance(original_request, Mapping):
        stored_original_request = original_request

    if state is None:
        return None, (
            advanced_module.jsonify(
                {
                    "error": (
                        "Registration state not found or has expired. "
                        "Please restart the registration process."
                    )
                }
            ),
            400,
        )

    stored_rp = advanced_module.session.pop("advanced_rp", None)
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

    resolved_rp_id = advanced_module.determine_rp_id(stored_rp_id)
    register_server = advanced_module.create_fido_server(rp_id=resolved_rp_id, rp_name=stored_rp_name)
    auth_data = register_server.register_complete(state, response)

    advanced_module._log_authenticator_attestation_response(
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
    }, None
