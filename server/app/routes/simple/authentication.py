"""The Simple tab's authentication: begin issues the options and keeps the ceremony's
state in the session; complete verifies the assertion, checks its backup flags
(``assertion_checks``: BS without BE is refused, a BE that is not the registration's is
its warning), then its user handle and its signature counter against the server's record
(``stored_sign_count``)."""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from typing import Any

from flask import Blueprint, jsonify, request, session

from ...challenge_registry import (
    CHALLENGE_FRESH,
    CHALLENGE_REPLAYED,
    consume_ceremony_state,
    stamp_ceremony_state,
)
from ...config import relying_party
from ...encoding import encode_base64url
from ...webauthn import assertion_checks, client_binary, client_credentials
from ...webauthn.attestation import error_codes
from .. import ceremony_errors, ceremony_session, json_body
from . import account, parsing, stored_sign_count

bp = Blueprint("simple_authentication", __name__)

logger = logging.getLogger(__name__)

# What begin keeps of the credentials it was sent: their digest. Their public keys
# (an ML-DSA-87 key is 2.6 KB) would not fit a cookie; complete is sent the same
# list again, and is refused when it is not the one begin built its options from.
_CREDENTIALS_DIGEST_KEY = "simple_credentials_digest"

# A begin sent no credential it could read: there is nothing to offer (the page says so on a 404).
NO_CREDENTIAL_SENT = "This browser sent no saved credential for this username."
# A complete with no ceremony begun in this session, or one that sent no credential to verify against.
STATE_NOT_FOUND = "Authentication state not found or has expired. Please restart the authentication flow."
NO_CREDENTIAL_TO_VERIFY = (
    "No saved credential was sent to verify the sign-in against. Please restart the authentication flow."
)


def credentials_digest(serialized: list[dict[str, Any]]) -> str:
    """The digest begin keeps of the credentials it read (``parsing._parse_client_credentials``)."""

    canonical = json.dumps(serialized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return encode_base64url(hashlib.sha256(canonical).digest())


@bp.route("/api/authenticate/begin", methods=["POST"])
@ceremony_session.ceremony_begin
def authenticate_begin():
    username, refusal = account.read_username(request.args.get("email"))
    if refusal is not None:
        return jsonify({"error": refusal}), 400
    payload = json_body.json_object()

    raw_credentials: list[Any] = []
    if isinstance(payload, Mapping):
        candidate_credentials = payload.get("credentials") or payload.get("storedCredentials")
        if isinstance(candidate_credentials, list):
            raw_credentials = candidate_credentials
    if client_credentials.too_many(raw_credentials):
        return jsonify({"error": client_credentials.TOO_MANY_CREDENTIALS}), 400

    credential_data_list, serialized = parsing._parse_client_credentials(raw_credentials)

    if not credential_data_list:
        return jsonify({"error": NO_CREDENTIAL_SENT}), 404

    session[_CREDENTIALS_DIGEST_KEY] = credentials_digest(serialized)
    session["simple_credentials_email"] = username

    rp_id = relying_party.determine_rp_id()
    server = relying_party.create_fido_server(rp_id=rp_id)

    options, state = server.authenticate_begin(
        credential_data_list,
        user_verification="discouraged",
    )
    # Stamped so /complete can refuse a stale state replayed from an old cookie.
    session["simple_authenticate_state"] = stamp_ceremony_state(dict(state))
    session["authenticate_rp_id"] = rp_id

    options_payload = dict(options)
    # The ceremony state (and therefore the challenge) stays server-side.

    return jsonify(options_payload)


def _challenge_rejection_message(replayed: bool) -> str:
    if replayed:
        return (
            "This authentication challenge has already been used. "
            "Please restart the authentication flow."
        )
    return "Authentication challenge has expired. Please restart the authentication flow."


def _consume_authentication_state(
    response: Any, sent_credentials: Any
) -> tuple[tuple[Any, Any, list[Any], Any] | None, Any]:
    """The ceremony state, the credentials (those sent again, when they are the ones
    begin read) and the RP ID; or the 400.

    The session keys are popped in this order whatever the outcome, so a
    request that fails leaves nothing of the ceremony behind.
    """

    # Popping the state is not enough on its own: the session is a client-side
    # cookie, so an earlier copy that still holds this state can be resent.
    # Consuming the challenge server-side -- before anything can fail -- is
    # what makes it single-use.
    state = session.pop("simple_authenticate_state", None)
    challenge_verdict = (
        consume_ceremony_state(state) if state is not None else None
    )

    begun_with = session.pop(_CREDENTIALS_DIGEST_KEY, None)
    if client_credentials.too_many(sent_credentials):
        session.pop("authenticate_rp_id", None)
        session.pop("simple_credentials_email", None)
        return None, (jsonify({"error": client_credentials.TOO_MANY_CREDENTIALS}), 400)
    credential_data_list, session_credentials = parsing._parse_client_credentials(sent_credentials)
    if begun_with is None or not credential_data_list:
        session.pop("authenticate_rp_id", None)
        session.pop("simple_credentials_email", None)
        sentence = STATE_NOT_FOUND if begun_with is None else NO_CREDENTIAL_TO_VERIFY
        return None, (jsonify({"error": sentence}), 400)

    # A client-supplied ``__session_state`` is stripped and ignored: accepting
    # it would let the caller choose the challenge it is verified against.
    if isinstance(response, Mapping):
        response.pop("__session_state", None)
    if state is None:
        session.pop("authenticate_rp_id", None)
        return None, (jsonify({"error": STATE_NOT_FOUND}), 400)

    rp_id = session.pop("authenticate_rp_id", None)
    if challenge_verdict != CHALLENGE_FRESH:
        session.pop("simple_credentials_email", None)
        return None, (
            jsonify(
                {
                    "error": _challenge_rejection_message(
                        challenge_verdict == CHALLENGE_REPLAYED
                    )
                }
            ),
            400,
        )
    # The email names whose stored records the counter is checked against: the one begin was for.
    begun_email = session.get("simple_credentials_email")
    if begun_email is None or begun_email != account.read_username(request.args.get("email"))[0]:
        session.pop("simple_credentials_email", None)
        return None, (
            jsonify({"error": "This authentication began for another email. Please restart the authentication flow."}),
            400,
        )
    if credentials_digest(session_credentials) != begun_with:
        session.pop("simple_credentials_email", None)
        return None, (
            jsonify(
                {
                    "error": (
                        "The saved credentials sent with this authentication are not the ones it began "
                        "with. Please restart the authentication flow."
                    )
                }
            ),
            400,
        )
    return (state, session_credentials, credential_data_list, rp_id), None


def _verify_assertion(
    state: Any, credential_data_list: list[Any], response: Any, response_mapping: Mapping[str, Any], rp_id: Any
) -> tuple[Any, Any]:
    """fido2's verification of the assertion: the credential it matched, or the 400 naming the one sent."""

    server = relying_party.create_fido_server(rp_id=rp_id)
    try:
        matched_credential = server.authenticate_complete(
            state,
            credential_data_list,
            response,
        )
    except Exception as exc:
        failed_credential_id = None
        credential_id_bytes = client_binary.extract_assertion_credential_id(response_mapping)
        if credential_id_bytes:
            failed_credential_id = (
                encode_base64url(credential_id_bytes)
            )

        response_payload: dict[str, Any] = {
            "error": ceremony_errors.answer_text(exc, ceremony_errors.AUTHENTICATION_FAILED)
        }
        if failed_credential_id is not None:
            response_payload["failedCredentialId"] = failed_credential_id

        session.pop("simple_credentials_email", None)
        return None, (jsonify(response_payload), 400)
    return matched_credential, None


def _matched_credential_id(matched_credential: Any) -> bytes:
    try:
        return bytes(getattr(matched_credential, "credential_id", b"") or b"")
    except Exception:
        return b""


def _backup_findings(
    auth_data: Any, session_credentials: list[Any], credential_id: bytes
) -> tuple[list[str], list[str]]:
    """The assertion's backup findings: the integrity errors, which refuse it, and the warnings.

    The BE the registration had is the one the page's record kept, sent with the credential.
    """

    entry = stored_sign_count.client_supplied_entry(session_credentials, credential_id) or {}
    errors, warnings = assertion_checks.backup_findings(auth_data, entry.get("backupEligible"))
    findings = error_codes.integrity_errors_only({"errors": errors, "warnings": warnings})
    return findings["errors"], findings["warnings"]


def _refused_assertion(authenticated_id: str, message: str, errors: list[str]) -> Any:
    """The 400 refusing an assertion its checks found an integrity error in."""

    logger.warning("Rejected assertion for credential %s: %s", authenticated_id, ", ".join(errors))
    return (
        jsonify({"error": message, "failedCredentialId": authenticated_id, "assertionErrors": errors}),
        400,
    )


@bp.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    # The browser's own JSON of the assertion, and the credentials begin was sent.
    body = json_body.json_object()
    response = body.get("credential")
    # Measured before the ceremony's state is consumed, as a body over the request limit is.
    too_large = ceremony_errors.authentication_response_too_large(response)
    if too_large is not None:
        return too_large

    consumed, error_response = _consume_authentication_state(response, body.get("credentials"))
    if error_response is not None:
        return error_response
    state, session_credentials, credential_data_list, rp_id = consumed

    response_mapping: Mapping[str, Any]
    response_mapping = response if isinstance(response, Mapping) else {}

    matched_credential, error_response = _verify_assertion(
        state, credential_data_list, response, response_mapping, rp_id
    )
    if error_response is not None:
        return error_response

    authenticated_id_bytes = _matched_credential_id(matched_credential)
    authenticated_id = (
        encode_base64url(authenticated_id_bytes)
        if authenticated_id_bytes
        else None
    )
    # The authenticatorData the signature was just verified over, and the userHandle.
    auth_data, user_handle = assertion_checks.assertion_parts(response_mapping)
    sign_count = auth_data.counter if auth_data is not None else None

    username = session.pop("simple_credentials_email", None)

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

    backup_errors, warnings = _backup_findings(auth_data, session_credentials, authenticated_id_bytes)
    if backup_errors:
        return _refused_assertion(
            encode_base64url(authenticated_id_bytes),
            "The authenticator data says this credential is backed up but not backup eligible, "
            "so authentication was rejected.",
            backup_errors,
        )

    rejection, sign_count_verdict, user_handle_status = stored_sign_count.enforce_sign_count(
        username,
        authenticated_id_bytes,
        sign_count,
        stored_sign_count.client_supplied_sign_count(session_credentials, authenticated_id_bytes),
        user_handle,
    )
    if rejection is not None:
        return rejection

    return jsonify(_authenticated_payload(authenticated_id, sign_count, sign_count_verdict, user_handle_status, warnings))


def _authenticated_payload(
    authenticated_id: str | None, sign_count: int, sign_count_verdict: str, user_handle_status: str, warnings: list[str]
) -> dict[str, Any]:
    """The answer to a verified assertion: the counter and what the check made of it, what the
    user handle check found, and the warnings when there are any."""

    payload: dict[str, Any] = {
        "status": "OK",
        "hintsUsed": [],
        "authenticatedCredentialId": authenticated_id,
        "signCount": sign_count,
        "signCountStatus": sign_count_verdict,
        "userHandleStatus": user_handle_status,
    }
    if warnings:
        payload["warnings"] = warnings
    return payload
