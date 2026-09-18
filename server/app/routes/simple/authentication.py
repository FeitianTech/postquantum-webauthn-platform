"""Signature-counter regression detection (WebAuthn L3 §7.2 step 21).

Where the "stored" counter comes from
-------------------------------------
The simple flow keeps two copies of each credential: the server-side record
written by ``savekey`` at registration, and the browser's own copy, which it
sends back as the credential list on ``/authenticate/begin``. The server record
is authoritative; the browser copy is attacker-controllable, so it may only
ever make the check *stricter*. The stored value is therefore the larger of the
two, and a missing copy simply does not contribute."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from flask import abort, jsonify, request, session

from fido2.webauthn import AuthenticatorData

from ... import attestation, config
from ...challenge_registry import (
    CHALLENGE_FRESH,
    CHALLENGE_REPLAYED,
    consume_ceremony_state,
    stamp_ceremony_state,
)
from ...encoding import encode_base64url
from ...storage import credentials
from ...webauthn import metadata
from ...webauthn.sign_count import SIGN_COUNT_REGRESSED, sign_count_status
from .. import binary_helpers
from . import binary, parsing


def authenticate_begin():
    uname = request.args.get("email")
    payload = request.get_json(silent=True) or {}

    raw_credentials: list[Any] = []
    if isinstance(payload, Mapping):
        candidate_credentials = payload.get("credentials") or payload.get("storedCredentials")
        if isinstance(candidate_credentials, list):
            raw_credentials = candidate_credentials

    credential_data_list, serialized = parsing._parse_client_credentials(raw_credentials)

    if not credential_data_list:
        abort(404)

    session["simple_credentials"] = serialized
    session["simple_credentials_email"] = uname

    rp_id = config.determine_rp_id()
    server = config.create_fido_server(rp_id=rp_id)

    options, state = server.authenticate_begin(
        credential_data_list,
        user_verification="discouraged",
    )
    # Stamped so /complete can refuse a stale state replayed from an old cookie.
    session["state"] = stamp_ceremony_state(dict(state))
    session["authenticate_rp_id"] = rp_id

    options_payload = dict(options)
    # The ceremony state (and therefore the challenge) stays server-side.

    return jsonify(attestation.make_json_safe(options_payload))


def _challenge_rejection_message(replayed: bool) -> str:
    if replayed:
        return (
            "This authentication challenge has already been used. "
            "Please restart the authentication flow."
        )
    return "Authentication challenge has expired. Please restart the authentication flow."


def authenticate_complete():
    response = request.get_json(silent=True)

    # Popping the state is not enough on its own: the session is a client-side
    # cookie, so an earlier copy that still holds this state can be resent.
    # Consuming the challenge server-side -- before anything can fail -- is
    # what makes it single-use.
    state = session.pop("state", None)
    challenge_verdict = (
        consume_ceremony_state(state) if state is not None else None
    )

    session_credentials = session.pop("simple_credentials", [])
    credential_data_list, _ = parsing._parse_client_credentials(session_credentials)
    if not credential_data_list:
        session.pop("authenticate_rp_id", None)
        session.pop("simple_credentials_email", None)
        abort(400)

    # A client-supplied ``__session_state`` is stripped and ignored: accepting
    # it would let the caller choose the challenge it is verified against.
    if isinstance(response, Mapping):
        response.pop("__session_state", None)
    if state is None:
        session.pop("authenticate_rp_id", None)
        return (
            jsonify(
                {
                    "error": "Authentication state not found or has expired. Please restart the authentication flow."
                }
            ),
            400,
        )

    rp_id = session.pop("authenticate_rp_id", None)
    if challenge_verdict != CHALLENGE_FRESH:
        session.pop("simple_credentials_email", None)
        return (
            jsonify(
                {
                    "error": _challenge_rejection_message(
                        challenge_verdict == CHALLENGE_REPLAYED
                    )
                }
            ),
            400,
        )

    server = config.create_fido_server(rp_id=rp_id)

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
        credential_id_bytes = binary_helpers.extract_assertion_credential_id(response_mapping)
        if credential_id_bytes:
            failed_credential_id = (
                encode_base64url(credential_id_bytes)
            )

        response_payload: dict[str, Any] = {"error": str(exc)}
        if failed_credential_id is not None:
            response_payload["failedCredentialId"] = failed_credential_id

        session.pop("simple_credentials_email", None)
        return jsonify(response_payload), 400

    try:
        authenticated_id_bytes = bytes(getattr(matched_credential, "credential_id", b"") or b"")
    except Exception:
        authenticated_id_bytes = b""
    authenticated_id = (
        encode_base64url(authenticated_id_bytes)
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
        sign_count = AuthenticatorData(
            binary_helpers.decode_base64url_bytes(auth_data_value)
        ).counter
    except Exception:
        sign_count = None

    uname = request.args.get("email")
    session.pop("simple_credentials_email", None)

    if sign_count is None or not authenticated_id_bytes:
        return (
            jsonify(
                {
                    "error": (
                        "The signature counter could not be read from the authenticator "
                        "data, so authentication was rejected."
                    )
                }
            ),
            400,
        )

    server_records, metadata_session_id = load_server_records(uname)
    record_index = find_server_record_index(server_records, authenticated_id_bytes)
    server_record = server_records[record_index] if record_index is not None else None
    stored_sign_count = resolve_stored_sign_count(
        server_record,
        client_supplied_sign_count(session_credentials, authenticated_id_bytes),
    )

    if sign_count_status(stored_sign_count, sign_count) == SIGN_COUNT_REGRESSED:
        config.app.logger.warning(
            "Rejected assertion for credential %s: signature counter %d did not "
            "increase past stored %d (possible cloned authenticator)",
            authenticated_id,
            sign_count,
            stored_sign_count,
        )
        return (
            jsonify(
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
            credentials.savekey(uname, server_records, session_id=metadata_session_id)
        except Exception:
            config.app.logger.exception(
                "Failed to persist signature counter for %s", authenticated_id
            )
            return (
                jsonify({"error": "Unable to persist the signature counter."}),
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

    return jsonify(response_payload)


RECORD_SIGN_COUNT_KEY = "sign_count"


def _as_counter(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def record_credential_id(record: Any) -> bytes | None:
    if not isinstance(record, Mapping):
        return None
    credential_id = getattr(record.get("credential_data"), "credential_id", None)
    if isinstance(credential_id, (bytes, bytearray, memoryview)):
        return bytes(credential_id)
    return None


def record_sign_count(record: Mapping[str, Any]) -> int | None:
    counter = _as_counter(record.get(RECORD_SIGN_COUNT_KEY))
    if counter is not None:
        return counter
    return _as_counter(getattr(record.get("auth_data"), "counter", None))


def load_server_records(uname: Any) -> tuple[list[Any] | None, str | None]:
    """Read the caller's server-side credential records, or ``(None, None)``."""

    if not isinstance(uname, str) or not uname:
        return None, None
    try:
        session_id = metadata.ensure_metadata_session_id()
        records = credentials.readkey(uname, session_id=session_id)
    except Exception:
        config.app.logger.warning(
            "Could not read stored credentials for the signature counter check", exc_info=True
        )
        return None, None
    if not isinstance(records, list):
        return None, None
    return records, session_id


def find_server_record_index(records: list[Any] | None, credential_id: bytes) -> int | None:
    if not records:
        return None
    for index, record in enumerate(records):
        if record_credential_id(record) == credential_id:
            return index
    return None


def client_supplied_sign_count(
    session_credentials: Iterable[Any], credential_id: bytes
) -> int | None:
    for entry in session_credentials or ():
        if not isinstance(entry, Mapping):
            continue
        raw_id = entry.get("credentialId")
        if raw_id is None:
            continue
        try:
            entry_id = binary._decode_binary_value(raw_id)
        except Exception:
            continue
        if entry_id == credential_id:
            return _as_counter(entry.get("signCount"))
    return None


def resolve_stored_sign_count(
    server_record: Mapping[str, Any] | None, client_supplied: int | None
) -> int:
    candidates = [
        value
        for value in (
            record_sign_count(server_record) if server_record is not None else None,
            client_supplied,
        )
        if value is not None
    ]
    return max(candidates) if candidates else 0
