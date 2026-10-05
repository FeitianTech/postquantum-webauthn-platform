"""The Simple tab's authentication: begin issues the options and keeps the ceremony's
state in the session; complete verifies the assertion and checks its signature counter
(``stored_sign_count``)."""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from typing import Any

from fido2.webauthn import AuthenticatorData
from flask import Blueprint, abort, jsonify, request, session

from ...challenge_registry import (
    CHALLENGE_FRESH,
    CHALLENGE_REPLAYED,
    consume_ceremony_state,
    stamp_ceremony_state,
)
from ...config import relying_party
from ...encoding import encode_base64url
from ...webauthn import client_binary
from .. import ceremony_session, json_body
from . import parsing, stored_sign_count

bp = Blueprint("simple_authentication", __name__)

logger = logging.getLogger(__name__)

# What begin keeps of the credentials it was sent: their digest. Their public keys
# (an ML-DSA-87 key is 2.6 KB) would not fit a cookie; complete is sent the same
# list again, and is refused when it is not the one begin built its options from.
_CREDENTIALS_DIGEST_KEY = "simple_credentials_digest"


def credentials_digest(serialized: list[dict[str, Any]]) -> str:
    """The digest begin keeps of the credentials it read (``parsing._parse_client_credentials``)."""

    canonical = json.dumps(serialized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return encode_base64url(hashlib.sha256(canonical).digest())


@bp.route("/api/authenticate/begin", methods=["POST"])
@ceremony_session.ceremony_begin
def authenticate_begin():
    uname = request.args.get("email")
    payload = json_body.json_object()

    raw_credentials: list[Any] = []
    if isinstance(payload, Mapping):
        candidate_credentials = payload.get("credentials") or payload.get("storedCredentials")
        if isinstance(candidate_credentials, list):
            raw_credentials = candidate_credentials

    credential_data_list, serialized = parsing._parse_client_credentials(raw_credentials)

    if not credential_data_list:
        abort(404)

    session[_CREDENTIALS_DIGEST_KEY] = credentials_digest(serialized)
    session["simple_credentials_email"] = uname

    rp_id = relying_party.determine_rp_id()
    server = relying_party.create_fido_server(rp_id=rp_id)

    options, state = server.authenticate_begin(
        credential_data_list,
        user_verification="discouraged",
    )
    # Stamped so /complete can refuse a stale state replayed from an old cookie.
    session["state"] = stamp_ceremony_state(dict(state))
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
    state = session.pop("state", None)
    challenge_verdict = (
        consume_ceremony_state(state) if state is not None else None
    )

    begun_with = session.pop(_CREDENTIALS_DIGEST_KEY, None)
    credential_data_list, session_credentials = parsing._parse_client_credentials(sent_credentials)
    if begun_with is None or not credential_data_list:
        session.pop("authenticate_rp_id", None)
        session.pop("simple_credentials_email", None)
        abort(400)

    # A client-supplied ``__session_state`` is stripped and ignored: accepting
    # it would let the caller choose the challenge it is verified against.
    if isinstance(response, Mapping):
        response.pop("__session_state", None)
    if state is None:
        session.pop("authenticate_rp_id", None)
        return None, (
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
    if session.get("simple_credentials_email") != request.args.get("email"):
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

        response_payload: dict[str, Any] = {"error": str(exc)}
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


def _asserted_sign_count(response_mapping: Mapping[str, Any]) -> int | None:
    """The counter in the authenticatorData the signature was just verified over; ``None`` if it does not read."""

    # It is base64url: the standard-alphabet decode used here previously
    # silently dropped '-' and '_' and could misread the counter.
    credential_response = response_mapping.get("response")
    auth_data_value = (
        credential_response.get("authenticatorData")
        if isinstance(credential_response, Mapping)
        else None
    )
    try:
        return AuthenticatorData(
            client_binary.decode_base64url_bytes(auth_data_value)
        ).counter
    except Exception:
        return None


@bp.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    # The browser's own JSON of the assertion, and the credentials begin was sent.
    body = json_body.json_object()
    response = body.get("credential")

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
    sign_count = _asserted_sign_count(response_mapping)

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

    rejection, sign_count_verdict = stored_sign_count.enforce_sign_count(
        uname,
        authenticated_id_bytes,
        sign_count,
        stored_sign_count.client_supplied_sign_count(session_credentials, authenticated_id_bytes),
    )
    if rejection is not None:
        return rejection

    return jsonify(_authenticated_payload(authenticated_id, sign_count, sign_count_verdict))


def _authenticated_payload(authenticated_id: str | None, sign_count: int, sign_count_verdict: str) -> dict[str, Any]:
    """The answer to a verified assertion, with the counter and what the check made of it."""

    return {
        "status": "OK",
        "hintsUsed": [],
        "authenticatedCredentialId": authenticated_id,
        "signCount": sign_count,
        "signCountStatus": sign_count_verdict,
    }
