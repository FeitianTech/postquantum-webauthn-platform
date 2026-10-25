"""Simple registration complete: saving the credential, and what follows a save.

The user's credential list is appended to by compare-and-swap, so concurrent
registrations for one user all keep their credential; then the device log is
updated. Each record keeps what the counter check reads
(``stored_sign_count.counter_record``), and the list's older records are brought
to that form as it is written.
"""
from __future__ import annotations

import logging
from typing import Any

from flask import jsonify

from ... import visitor_session
from ...storage import credentials, github_mirror
from ...storage.common import InvalidStorageIdentifier, StorageReadError
from ...webauthn import client_binary
from . import stored_sign_count
from .registration_record import SimpleRegistration

logger = logging.getLogger(__name__)

# A registration appends to the user's stored list by compare-and-swap. It loses
# only when another write landed between its read and its save, and each of those
# writers saves once, so N registrations racing for one user lose at most N - 1
# times each. Eight covers eight at once in one browser namespace.
_CREDENTIAL_SAVE_ATTEMPTS = 8
_PERSIST_FAILED = "Unable to persist registered credential."


def _build_credential_entry(reg: SimpleRegistration) -> dict[str, Any]:
    return stored_sign_count.counter_record(
        reg.auth_data.credential_data.credential_id,
        # Advanced on every successful authentication; see authenticate.
        int(getattr(reg.auth_data, "counter", 0)),
        reg.credential_info["registration_time"],
        reg.user_id,
    )


def _credential_is_stored(uname: str, credential_id: bytes, metadata_session_id: str) -> bool:
    """Whether a save that raised had landed anyway (a reply lost after the write)."""

    try:
        records = credentials.readkey(uname, session_id=metadata_session_id)
    except Exception:
        return False
    return any(stored_sign_count.record_credential_id(record) == credential_id for record in records)


def _persist_registered_credential_entry(reg: SimpleRegistration) -> Any | None:
    metadata_session_id = visitor_session.ensure_id()
    uname = reg.uname
    credential_entry = _build_credential_entry(reg)

    for _attempt in range(_CREDENTIAL_SAVE_ATTEMPTS):
        try:
            records, version = credentials.read_for_update(uname, session_id=metadata_session_id)
        except (InvalidStorageIdentifier, StorageReadError):
            # A name the store refuses is the caller's error (400); a store that
            # could not be read is not (503). routes/errors.py answers both.
            raise
        except credentials.CredentialsUndecodable as exc:
            # The current copy exists but does not decode: appending would replace
            # it unread. Unreadable, as authentication treats it.
            raise StorageReadError(str(exc)) from exc
        except Exception:
            # Never append to an empty list read in error: the save would
            # replace every credential the user has.
            logger.exception("Failed to read the stored credentials of %s", uname)
            return jsonify({"error": _PERSIST_FAILED}), 500

        saved = [*(stored_sign_count.as_counter_record(record) for record in records), credential_entry]
        try:
            if credentials.save_if_unchanged(uname, saved, version, session_id=metadata_session_id):
                return None
        except Exception:
            if _credential_is_stored(uname, bytes(reg.auth_data.credential_data.credential_id), metadata_session_id):
                return None
            logger.exception("Failed to persist registered credential for %s", uname)
            return jsonify({"error": _PERSIST_FAILED}), 500
        logger.info("The stored credentials of %s changed while saving a registration; reading them again", uname)

    logger.warning("Rejected a registration for %s: its stored credentials kept changing", uname)
    return (
        jsonify(
            {
                "error": (
                    "The stored credentials changed while this one was being saved, too many times, "
                    "so the registration was not saved. Please try again."
                )
            }
        ),
        409,
    )


def _record_registration_event(reg: SimpleRegistration) -> None:
    event = github_mirror.registration_event(
        rp_id=reg.resolved_rp_id,
        aaguid=reg.aaguid_bytes,
        metadata_summary=reg.metadata_summary,
        attestation_object=client_binary.decode_base64url_bytes(reg.raw_attestation_object_b64),
        signature_valid=reg.attestation_signature_valid,
        root_valid=reg.attestation_root_valid,
        rp_id_hash_valid=reg.attestation_rp_id_hash_valid,
        aaguid_match=reg.attestation_aaguid_match,
    )

    github_mirror.record_registration_event(event)


def persist_registration_context(reg: SimpleRegistration) -> Any | None:
    persist_response = _persist_registered_credential_entry(reg)
    if persist_response is not None:
        return persist_response

    _record_registration_event(reg)
    return None

