from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ...sign_count import SIGN_COUNT_REGRESSED, sign_count_status
from .sign_count_impl import (
    RECORD_SIGN_COUNT_KEY,
    client_supplied_sign_count_impl,
    find_server_record_index,
    load_server_records_impl,
    record_sign_count,
    resolve_stored_sign_count,
)


def authenticate_begin_impl(simple_module: Any):
    uname = simple_module.request.args.get("email")
    payload = simple_module.request.get_json(silent=True) or {}

    raw_credentials: list[Any] = []
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
    # Stamped so /complete can refuse a stale state replayed from an old cookie.
    simple_module.session["state"] = simple_module.stamp_ceremony_state(dict(state))
    simple_module.session["authenticate_rp_id"] = rp_id

    options_payload = dict(options)
    # The ceremony state (and therefore the challenge) stays server-side.

    return simple_module.jsonify(simple_module.make_json_safe(options_payload))


def _challenge_rejection_message(replayed: bool) -> str:
    if replayed:
        return (
            "This authentication challenge has already been used. "
            "Please restart the authentication flow."
        )
    return "Authentication challenge has expired. Please restart the authentication flow."


def authenticate_complete_impl(simple_module: Any):
    response = simple_module.request.get_json(silent=True)

    # Popping the state is not enough on its own: the session is a client-side
    # cookie, so an earlier copy that still holds this state can be resent.
    # Consuming the challenge server-side -- before anything can fail -- is
    # what makes it single-use.
    state = simple_module.session.pop("state", None)
    challenge_verdict = (
        simple_module.consume_ceremony_state(state) if state is not None else None
    )

    session_credentials = simple_module.session.pop("simple_credentials", [])
    credential_data_list, _ = simple_module._parse_client_credentials(session_credentials)
    if not credential_data_list:
        simple_module.session.pop("authenticate_rp_id", None)
        simple_module.session.pop("simple_credentials_email", None)
        simple_module.abort(400)

    # A client-supplied ``__session_state`` is stripped and ignored: accepting
    # it would let the caller choose the challenge it is verified against.
    if isinstance(response, Mapping):
        response.pop("__session_state", None)
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
    if challenge_verdict != simple_module.CHALLENGE_FRESH:
        simple_module.session.pop("simple_credentials_email", None)
        return (
            simple_module.jsonify(
                {
                    "error": _challenge_rejection_message(
                        challenge_verdict == simple_module.CHALLENGE_REPLAYED
                    )
                }
            ),
            400,
        )

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

        response_payload: dict[str, Any] = {"error": str(exc)}
        if failed_credential_id is not None:
            response_payload["failedCredentialId"] = failed_credential_id

        simple_module.session.pop("simple_credentials_email", None)
        return simple_module.jsonify(response_payload), 400

    try:
        authenticated_id_bytes = bytes(getattr(matched_credential, "credential_id", b"") or b"")
    except Exception:
        authenticated_id_bytes = b""
    authenticated_id = (
        simple_module.base64.urlsafe_b64encode(authenticated_id_bytes).decode("ascii").rstrip("=")
        if authenticated_id_bytes
        else None
    )

    # The counter comes from the authenticatorData the signature was just
    # verified over. It is base64url: the standard-alphabet decode used here
    # previously silently dropped '-' and '_' and could misread the counter.
    credential_response = response_mapping.get("response")
    auth_data_value = (
        credential_response.get("authenticatorData")
        if isinstance(credential_response, Mapping)
        else None
    )
    try:
        sign_count = simple_module.AuthenticatorData(
            simple_module._decode_base64url_bytes(auth_data_value)
        ).counter
    except Exception:
        sign_count = None

    uname = simple_module.request.args.get("email")
    simple_module.session.pop("simple_credentials_email", None)

    if sign_count is None or not authenticated_id_bytes:
        return (
            simple_module.jsonify(
                {
                    "error": (
                        "The signature counter could not be read from the authenticator "
                        "data, so authentication was rejected."
                    )
                }
            ),
            400,
        )

    server_records, metadata_session_id = load_server_records_impl(simple_module, uname)
    record_index = find_server_record_index(server_records, authenticated_id_bytes)
    server_record = server_records[record_index] if record_index is not None else None
    stored_sign_count = resolve_stored_sign_count(
        server_record,
        client_supplied_sign_count_impl(simple_module, session_credentials, authenticated_id_bytes),
    )

    if sign_count_status(stored_sign_count, sign_count) == SIGN_COUNT_REGRESSED:
        simple_module.app.logger.warning(
            "Rejected assertion for credential %s: signature counter %d did not "
            "increase past stored %d (possible cloned authenticator)",
            authenticated_id,
            sign_count,
            stored_sign_count,
        )
        return (
            simple_module.jsonify(
                {
                    "error": (
                        f"Signature counter did not increase (stored {stored_sign_count}, "
                        f"received {sign_count}). This authenticator may have been cloned, "
                        "so authentication was rejected."
                    ),
                    "failedCredentialId": authenticated_id,
                    "signCountStatus": SIGN_COUNT_REGRESSED,
                }
            ),
            400,
        )

    if server_record is not None and record_sign_count(server_record) != sign_count:
        server_record[RECORD_SIGN_COUNT_KEY] = sign_count
        try:
            simple_module.savekey(uname, server_records, session_id=metadata_session_id)
        except Exception:
            simple_module.app.logger.exception(
                "Failed to persist signature counter for %s", authenticated_id
            )
            return (
                simple_module.jsonify({"error": "Unable to persist the signature counter."}),
                500,
            )

    debug_info = {
        "hintsUsed": [],
    }

    response_payload: dict[str, Any] = {
        "status": "OK",
        **debug_info,
    }
    response_payload["authenticatedCredentialId"] = authenticated_id
    response_payload["signCount"] = sign_count

    return simple_module.jsonify(response_payload)
