from __future__ import annotations

from typing import Any, Dict, List, Mapping


def authenticate_begin_impl(simple_module: Any):
    uname = simple_module.request.args.get("email")
    payload = simple_module.request.get_json(silent=True) or {}

    raw_credentials: List[Any] = []
    if isinstance(payload, Mapping):
        candidate_credentials = payload.get("credentials") or payload.get("storedCredentials")
        if isinstance(candidate_credentials, list):
            raw_credentials = candidate_credentials

    credential_data_list, serialized = simple_module._parse_client_credentials(raw_credentials)

    if not credential_data_list:
        simple_module.abort(404)

    simple_module.session["simple_credentials"] = serialized
    simple_module.session["simple_credentials_email"] = uname

    rp_id = simple_module.determine_rp_id()
    server = simple_module.create_fido_server(rp_id=rp_id)

    options, state = server.authenticate_begin(
        credential_data_list,
        user_verification="discouraged",
    )
    simple_module.session["state"] = state
    simple_module.session["authenticate_rp_id"] = rp_id

    options_payload = dict(options)
    options_payload["__session_state"] = simple_module.make_json_safe(state)

    return simple_module.jsonify(simple_module.make_json_safe(options_payload))


def authenticate_complete_impl(simple_module: Any):
    response = simple_module.request.get_json(silent=True)
    session_credentials = simple_module.session.pop("simple_credentials", [])
    credential_data_list, _ = simple_module._parse_client_credentials(session_credentials)
    if not credential_data_list:
        simple_module.abort(400)

    state = simple_module.session.pop("state", None)
    state_from_request = None
    if isinstance(response, Mapping):
        state_from_request = response.pop("__session_state", None)
    if state is None and isinstance(state_from_request, Mapping):
        state = state_from_request
    if state is None:
        simple_module.session.pop("authenticate_rp_id", None)
        return (
            simple_module.jsonify(
                {
                    "error": "Authentication state not found or has expired. Please restart the authentication flow."
                }
            ),
            400,
        )

    rp_id = simple_module.session.pop("authenticate_rp_id", None)
    server = simple_module.create_fido_server(rp_id=rp_id)

    response_mapping: Mapping[str, Any]
    response_mapping = response if isinstance(response, Mapping) else {}

    try:
        matched_credential = server.authenticate_complete(
            state,
            credential_data_list,
            response,
        )
    except Exception as exc:
        failed_credential_id = None
        credential_id_bytes = simple_module._extract_assertion_credential_id(response_mapping)
        if credential_id_bytes:
            failed_credential_id = (
                simple_module.base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")
            )

        response_payload: Dict[str, Any] = {"error": str(exc)}
        if failed_credential_id is not None:
            response_payload["failedCredentialId"] = failed_credential_id

        simple_module.session.pop("simple_credentials_email", None)
        return simple_module.jsonify(response_payload), 400

    credential_response = (
        response_mapping.get("response", {}) if isinstance(response_mapping, Mapping) else {}
    )
    auth_data_b64 = (
        credential_response.get("authenticatorData") if isinstance(credential_response, Mapping) else None
    )
    sign_count = None
    if isinstance(auth_data_b64, str):
        try:
            auth_data_bytes = simple_module.base64.b64decode(simple_module._add_base64_padding(auth_data_b64))
            sign_count = simple_module.AuthenticatorData(auth_data_bytes).counter
        except Exception:
            sign_count = None

    authenticated_id = None
    try:
        credential_id_bytes = bytes(getattr(matched_credential, "credential_id", b""))
        if credential_id_bytes:
            authenticated_id = simple_module.base64.urlsafe_b64encode(credential_id_bytes).decode("ascii").rstrip("=")
    except Exception:
        authenticated_id = None

    debug_info = {
        "hintsUsed": [],
    }

    response_payload: Dict[str, Any] = {
        "status": "OK",
        **debug_info,
    }
    if authenticated_id is not None:
        response_payload["authenticatedCredentialId"] = authenticated_id
    if sign_count is not None:
        response_payload["signCount"] = sign_count

    simple_module.session.pop("simple_credentials_email", None)

    return simple_module.jsonify(response_payload)
