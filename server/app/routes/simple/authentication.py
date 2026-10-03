"""Signature-counter regression detection (WebAuthn L3 §7.2 step 21).

Where the "stored" counter comes from
-------------------------------------
The simple flow keeps two copies of each credential: the server-side record
written at registration, and the browser's own copy, which it
sends back as the credential list on ``/authenticate/begin`` and again, the same
list, on ``/authenticate/complete``. The server record
is authoritative; the browser copy is attacker-controllable, so it may only
ever make the check *stricter*. The stored value is therefore the larger of the
two, and a missing copy simply does not contribute.

"Missing" means the server's records were read and hold no record for the
credential. Records that could not be read are not missing: the assertion is
rejected with 503, since the browser's copy alone can be omitted or lowered."""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Mapping
from typing import Any

from fido2.webauthn import AuthenticatorData
from flask import Blueprint, abort, jsonify, request, session

from ... import visitor_session
from ...challenge_registry import (
    CHALLENGE_FRESH,
    CHALLENGE_REPLAYED,
    consume_ceremony_state,
    stamp_ceremony_state,
)
from ...config import relying_party
from ...encoding import encode_base64url
from ...storage import credentials
from ...storage.common import InvalidStorageIdentifier
from ...webauthn import client_binary
from ...webauthn.sign_count import SIGN_COUNT_REGRESSED, sign_count_status
from .. import ceremony_session
from . import parsing

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
    payload = request.get_json(silent=True) or {}

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
    body = request.get_json(silent=True)
    body = body if isinstance(body, Mapping) else {}
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

    rejection, sign_count_verdict = enforce_sign_count(
        uname,
        authenticated_id_bytes,
        sign_count,
        client_supplied_sign_count(session_credentials, authenticated_id_bytes),
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


def enforce_sign_count(uname: Any, credential_id: bytes, sign_count: int, client_sign_count: int | None):
    """Check ``sign_count`` against the stored counter and store it.

    Returns ``(rejection, status)``: the response to answer instead (or ``None``)
    and, when the assertion is accepted, the counter status it was accepted with.
    """

    authenticated_id = encode_base64url(credential_id)
    # Check-then-save is compare-and-swap: two authentications that both read
    # counter N cannot both store N+1. The one that loses reads the records
    # again and is checked again -- against the counter the other just stored.
    for _attempt in range(_SIGN_COUNT_SAVE_ATTEMPTS):
        try:
            server_records, version, metadata_session_id = load_server_records(uname)
        except StoredRecordsUnreadable as exc:
            return _unreadable_counter_rejection(authenticated_id, exc), None
        record_index = find_server_record_index(server_records, credential_id)
        server_record = server_records[record_index] if record_index is not None else None
        stored_sign_count = resolve_stored_sign_count(server_record, client_sign_count)

        verdict = sign_count_status(stored_sign_count, sign_count)
        if verdict == SIGN_COUNT_REGRESSED:
            return _regressed_counter_rejection(authenticated_id, stored_sign_count, sign_count), verdict

        if server_record is None or record_sign_count(server_record) == sign_count:
            return None, verdict
        server_record[RECORD_SIGN_COUNT_KEY] = sign_count
        try:
            if credentials.save_if_unchanged(uname, server_records, version, session_id=metadata_session_id):
                return None, verdict
        except Exception:
            logger.exception(
                "Failed to persist signature counter for %s", authenticated_id
            )
            return (
                jsonify({"error": "Unable to persist the signature counter."}),
                500,
            ), None
        logger.info("Signature counter for %s changed while it was being saved; reading it again", authenticated_id)

    logger.warning("Rejected assertion for credential %s: its stored counter kept changing", authenticated_id)
    return (
        jsonify(
            {
                "error": (
                    "The stored signature counter changed during authentication more than "
                    "once, so authentication was rejected. Please try again."
                ),
                "failedCredentialId": authenticated_id,
            }
        ),
        409,
    ), None


def _unreadable_counter_rejection(authenticated_id: str, exc: Exception):
    # Checking against the browser's copy alone would let a client that omits
    # or lowers it past the check whenever the store is down. One line, no
    # traceback: the cause is the store's, and it is named.
    logger.warning(
        "Rejected assertion for credential %s: the stored signature counter could not be read (%r)",
        authenticated_id,
        exc.__cause__ or exc,
    )
    return (
        jsonify(
            {
                "error": (
                    "The stored signature counter could not be read, so authentication "
                    "was rejected. Please try again."
                )
            }
        ),
        503,
    )


def _regressed_counter_rejection(authenticated_id: str, stored_sign_count: int, sign_count: int):
    logger.warning(
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


RECORD_SIGN_COUNT_KEY = "sign_count"
# A lost compare-and-swap is retried once; losing twice rejects the assertion.
_SIGN_COUNT_SAVE_ATTEMPTS = 2


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


class StoredRecordsUnreadable(Exception):
    """The server's records could not be read: the counter check cannot be made."""


def load_server_records(uname: Any) -> tuple[list[Any] | None, Any, str | None]:
    """The caller's server-side records, their version, the session: ``(None, None, None)`` if none.

    "None" means the read worked and there is nothing to find (or no name or
    namespace to find it by). A read that failed raises :class:`StoredRecordsUnreadable`.
    """

    # A visitor without a namespace has stored nothing, and reading gives them none.
    session_id = visitor_session.current_id()
    if not isinstance(uname, str) or not uname or not session_id:
        return None, None, None
    try:
        records, version = credentials.read_for_update(uname, session_id=session_id)
    except InvalidStorageIdentifier:
        # A name the store refuses is the caller's error: the app answers 400.
        raise
    except Exception as exc:
        raise StoredRecordsUnreadable() from exc
    if not isinstance(records, list):
        raise StoredRecordsUnreadable(f"the store answered {type(records).__name__}, not a list")
    return records, version, session_id


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
            entry_id = client_binary.read(raw_id, iterables=True)
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
