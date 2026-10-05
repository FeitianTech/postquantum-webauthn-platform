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

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from flask import jsonify

from ... import visitor_session
from ...encoding import encode_base64url
from ...storage import credentials
from ...storage.common import InvalidStorageIdentifier
from ...webauthn import client_binary
from ...webauthn.sign_count import SIGN_COUNT_REGRESSED, sign_count_status

logger = logging.getLogger(__name__)


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
