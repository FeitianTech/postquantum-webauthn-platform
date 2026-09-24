"""Simple registration complete: saving the credential, and what follows a save.

The user's credential list is appended to by compare-and-swap, so concurrent
registrations for one user all keep their credential; then the session's
credential list and the device log are updated.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from flask import jsonify, session

from ... import device_logs
from ...storage import credentials
from ...storage.common import InvalidStorageIdentifier, StorageReadError
from ...webauthn import attestation, metadata
from .. import binary_helpers

logger = logging.getLogger(__name__)

# A registration appends to the user's stored list by compare-and-swap. It loses
# only when another write landed between its read and its save, and each of those
# writers saves once, so N registrations racing for one user lose at most N - 1
# times each. Eight covers eight at once in one browser namespace.
_CREDENTIAL_SAVE_ATTEMPTS = 8
_PERSIST_FAILED = "Unable to persist registered credential."


def _build_credential_entry(ctx: dict[str, Any]) -> dict[str, Any]:
    credential_entry = {
        "credential_data": ctx["auth_data"].credential_data,
        "auth_data": ctx["auth_data"],
        # Advanced on every successful authentication; see authenticate.
        "sign_count": int(getattr(ctx["auth_data"], "counter", 0)),
        "user_info": ctx["credential_info"]["user_info"],
        "registration_time": ctx["credential_info"]["registration_time"],
        "client_data_json": ctx["credential_info"].get("client_data_json", ""),
        "attestation_object": ctx["credential_info"].get("attestation_object", ""),
        "attestation_object_raw": ctx["credential_info"].get("attestation_object_raw", ""),
        "attestation_format": ctx["attestation_format"],
        "attestation_statement": ctx["attestation_statement"],
        "attestation_certificate": ctx["attestation_certificate_details"],
        "attestation_certificates": ctx["attestation_certificates_details"],
        "client_extension_outputs": ctx["client_extension_results"],
        "authenticator_attachment": ctx["authenticator_attachment_response"],
        "request_params": ctx["credential_info"].get("request_params", {}),
        "properties": ctx["credential_properties"],
        "relying_party": ctx["credential_info"].get("relying_party"),
        "registration_response": ctx["credential_info"].get("registration_response"),
    }

    if ctx["parsed_attestation_object"]:
        credential_entry["attestation_object_decoded"] = attestation.make_json_safe(
            ctx["parsed_attestation_object"]
        )
    return credential_entry


def _credential_is_stored(uname: str, credential_id: bytes, metadata_session_id: str) -> bool:
    """Whether a save that raised had landed anyway (a reply lost after the write)."""

    try:
        records = credentials.readkey(uname, session_id=metadata_session_id)
    except Exception:
        return False
    return any(
        bytes(getattr(record.get("credential_data"), "credential_id", b"") or b"") == credential_id
        for record in records
        if isinstance(record, Mapping)
    )


def _persist_registered_credential_entry(ctx: dict[str, Any]) -> Any | None:
    metadata_session_id = metadata.ensure_metadata_session_id()
    uname = ctx["uname"]
    credential_entry = _build_credential_entry(ctx)

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

        try:
            if credentials.save_if_unchanged(uname, [*records, credential_entry], version, session_id=metadata_session_id):
                return None
        except Exception:
            if _credential_is_stored(uname, bytes(ctx["auth_data"].credential_data.credential_id), metadata_session_id):
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


def _update_session_simple_credentials(ctx: dict[str, Any]) -> None:
    session_simple_credentials = session.get("simple_credentials")
    if isinstance(session_simple_credentials, list):
        new_entry = {
            "credentialId": ctx["stored_credential"]["credentialIdBase64Url"],
            "aaguid": ctx["stored_credential"].get("aaguid"),
            "publicKey": ctx["stored_credential"]["publicKeyBase64Url"],
            "algorithm": ctx["stored_credential"].get("publicKeyAlgorithm"),
            "signCount": ctx["stored_credential"].get("signCount", 0),
            "email": ctx["stored_credential"].get("email"),
            "type": "simple",
        }
        session_simple_credentials = [
            entry for entry in session_simple_credentials if isinstance(entry, Mapping)
        ]
        session_simple_credentials.append(new_entry)
        session["simple_credentials"] = session_simple_credentials


def _record_registration_event(ctx: dict[str, Any]) -> None:
    metadata_description: str | None = None
    if isinstance(ctx["metadata_summary"], Mapping):
        raw_description = ctx["metadata_summary"].get("description")
        if isinstance(raw_description, str):
            metadata_description = raw_description

    transports_field = ctx["response"].get("transports") if isinstance(ctx["response"], Mapping) else None
    transports: list[str] | None = None
    if isinstance(transports_field, list):
        transports = [str(item) for item in transports_field if isinstance(item, str)]

    event = device_logs.RegistrationEvent(
        timestamp=datetime.now(timezone.utc),
        rp_id=ctx["resolved_rp_id"],
        user_id=ctx["user_handle_bytes"],
        user_name=str(ctx["uname"] or ""),
        user_display_name=str(
            ctx["credential_info"]["user_info"].get("display_name") or ctx["uname"] or ""
        ),
        credential_id=ctx["credential_id_bytes"],
        public_key_cose=ctx["cose_public_key"],
        sign_count=int(getattr(ctx["auth_data"], "counter", 0)),
        transports=transports,
        aaguid=ctx["aaguid_bytes"] or None,
        device_name_mds=metadata_description,
        attestation_format=str(ctx["attestation_format"] or ""),
        attestation_object=binary_helpers.decode_base64url_bytes(ctx["raw_attestation_object_b64"]),
        client_data_json=binary_helpers.decode_base64url_bytes(ctx["client_data_json_b64"]),
        signature_valid=ctx["attestation_signature_valid"],
        root_valid=ctx["attestation_root_valid"],
        rp_id_hash_valid=ctx["attestation_rp_id_hash_valid"],
        aaguid_match=ctx["attestation_aaguid_match"],
    )

    device_logs.record_registration_event(event)


def persist_registration_context(ctx: dict[str, Any]) -> Any | None:
    persist_response = _persist_registered_credential_entry(ctx)
    if persist_response is not None:
        return persist_response

    _update_session_simple_credentials(ctx)
    _record_registration_event(ctx)
    return None

