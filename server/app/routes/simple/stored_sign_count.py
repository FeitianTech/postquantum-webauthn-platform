"""The Simple tab's checks against the server's record of a credential: its user handle
(WebAuthn L3 §7.2 step 6) and signature-counter regression (§7.2 step 21).

The user handle
---------------
The Simple tab names the account before the ceremony, so a userHandle the assertion
carries must be the one the account's record keeps: another refuses the sign-in. None
is compared without a record (a namespace swept), or with a record that keeps none, or
keeps its username's bytes: before each account had a handle of its own, registrations
gave the authenticator ``b"user_id"`` and kept the username's bytes, which no
authenticator was given.

Where the "stored" counter comes from
-------------------------------------
The simple flow keeps two copies of each credential: the server-side record
written at registration, and the browser's own copy, which it
sends back as the credential list on ``/authenticate/begin`` and again, the same
list, on ``/authenticate/complete``. The server record
is authoritative; the browser copy is attacker-controllable, so it may only
ever make the check *stricter*. The stored value is therefore the larger of the
two, and a missing copy simply does not contribute.

The server's record keeps what this check reads, the credential's ID and its
counter, and beside them when it was registered and its user handle
(``counter_record``): nothing else of the registration, which the browser keeps.
A record an earlier version stored whole is read the same way, and brought to
that form when its file is next written (``as_counter_record``).

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
from ...webauthn import assertion_checks, client_binary
from ...webauthn.sign_count import SIGN_COUNT_REGRESSED, sign_count_status

logger = logging.getLogger(__name__)


def enforce_sign_count(
    uname: Any, credential_id: bytes, sign_count: int, client_sign_count: int | None, user_handle: bytes | None = None
):
    """Check the assertion's ``user_handle``, then ``sign_count`` against the stored counter, and store it.

    Returns ``(rejection, status, user_handle_status)``: the response to answer instead
    (or ``None``), the counter status when the assertion is accepted, and what the user
    handle check found (``assertion_checks``).
    """

    authenticated_id = encode_base64url(credential_id)
    # Check-then-save is compare-and-swap: two authentications that both read
    # counter N cannot both store N+1. The one that loses reads the records
    # again and is checked again -- against the counter the other just stored.
    for _attempt in range(_SIGN_COUNT_SAVE_ATTEMPTS):
        try:
            server_records, version, metadata_session_id = load_server_records(uname)
        except StoredRecordsUnreadable as exc:
            return _unreadable_counter_rejection(authenticated_id, exc), None, None
        record_index = find_server_record_index(server_records, credential_id)
        server_record = server_records[record_index] if record_index is not None else None
        handle_status = assertion_checks.user_handle_status(user_handle, account_user_handle(server_record, uname))
        if handle_status == assertion_checks.USER_HANDLE_MISMATCH:
            return _user_handle_rejection(authenticated_id, handle_status), None, handle_status
        stored_sign_count = resolve_stored_sign_count(server_record, client_sign_count)

        verdict = sign_count_status(stored_sign_count, sign_count)
        if verdict == SIGN_COUNT_REGRESSED:
            return _regressed_counter_rejection(authenticated_id, stored_sign_count, sign_count), verdict, handle_status

        if server_record is None or record_sign_count(server_record) == sign_count:
            return None, verdict, handle_status
        server_record[RECORD_SIGN_COUNT_KEY] = sign_count
        try:
            saved = [as_counter_record(record) for record in server_records]
            if credentials.save_if_unchanged(uname, saved, version, session_id=metadata_session_id):
                return None, verdict, handle_status
        except Exception:
            logger.exception(
                "Failed to persist signature counter for %s", authenticated_id
            )
            return (
                jsonify({"error": "Unable to persist the signature counter."}),
                500,
            ), None, None
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
    ), None, None


def _user_handle_rejection(authenticated_id: str, handle_status: str):
    logger.warning("Rejected assertion for credential %s: its user handle is not the account's", authenticated_id)
    return (
        jsonify(
            {
                "error": (
                    "The user handle the authenticator returned is not this account's, "
                    "so authentication was rejected."
                ),
                "failedCredentialId": authenticated_id,
                "assertionErrors": assertion_checks.user_handle_findings(handle_status),
                "userHandleStatus": handle_status,
            }
        ),
        400,
    )


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
RECORD_CREDENTIAL_ID_KEY = "credential_id"
# A lost compare-and-swap is retried once; losing twice rejects the assertion.
_SIGN_COUNT_SAVE_ATTEMPTS = 2


def _as_counter(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def counter_record(credential_id: bytes, sign_count: int | None, registration_time: Any, user_handle: Any) -> dict[str, Any]:
    """The record the server keeps of a Simple credential."""

    return {
        RECORD_CREDENTIAL_ID_KEY: bytes(credential_id),
        RECORD_SIGN_COUNT_KEY: sign_count,
        "registration_time": registration_time,
        "user_handle": user_handle,
    }


def as_counter_record(record: Any) -> Any:
    """``record`` in the form ``counter_record`` gives; one whose credential ID cannot be read, as it is."""

    credential_id = record_credential_id(record)
    if credential_id is None:
        return record
    return counter_record(credential_id, record_sign_count(record), record.get("registration_time"), record_user_handle(record))


def record_user_handle(record: Mapping[str, Any]) -> Any:
    """The user handle a record keeps: its own, or (stored whole) its user information's."""

    user_handle = record.get("user_handle")
    user_info = record.get("user_info")
    if user_handle is None and isinstance(user_info, Mapping):
        user_handle = user_info.get("user_handle")
    return user_handle


def account_user_handle(record: Mapping[str, Any] | None, uname: Any) -> bytes | None:
    """The user handle the account gave the authenticator, as ``record`` keeps it; None when
    there is no record, or it keeps none, or keeps its username's bytes (records stored before
    each account had a handle of its own: their authenticators were given ``b"user_id"``)."""

    handle = record_user_handle(record) if record is not None else None
    if not isinstance(handle, (bytes, bytearray, memoryview)):
        return None
    if isinstance(uname, str) and bytes(handle) == uname.encode("utf-8"):
        return None
    return bytes(handle)


def record_credential_id(record: Any) -> bytes | None:
    """The credential ID a record names: its own, or (stored whole) its credential data's."""

    if not isinstance(record, Mapping):
        return None
    credential_id = record.get(RECORD_CREDENTIAL_ID_KEY)
    if credential_id is None:
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


def client_supplied_entry(session_credentials: Iterable[Any], credential_id: bytes) -> Mapping[str, Any] | None:
    """The entry the browser sent for ``credential_id``; None when it sent none."""

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
            return entry
    return None


def client_supplied_sign_count(
    session_credentials: Iterable[Any], credential_id: bytes
) -> int | None:
    entry = client_supplied_entry(session_credentials, credential_id)
    return _as_counter(entry.get("signCount")) if entry is not None else None


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
