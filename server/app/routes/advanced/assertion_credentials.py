"""Advanced authentication: which stored credentials an assertion may use.

Begin picks the credentials to offer (the allow list, else every stored or every
discoverable credential, filtered by the attachments the hints allow) and says
why when none qualify. Complete restores the credentials the request carries
(or, failing that, the legacy session copy) and checks a discoverable-only
ceremony was answered by a discoverable credential.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from flask import jsonify, session

from ...encoding import decode_hex, encode_base64url
from . import binary, parsing

_CREDENTIAL_FIELDS = ("__storedCredentials", "storedCredentials", "credentials")


def credential_list_input(data: Mapping[str, Any]) -> list[Any] | None:
    """The first credential list the request carries, under any of its accepted names."""

    for field in _CREDENTIAL_FIELDS:
        candidate = data.get(field)
        if isinstance(candidate, list):
            return candidate
    return None


def credential_lookup(stored_records: Iterable[Mapping[str, Any]]) -> dict[bytes, Any]:
    return {
        bytes(record["id"]): record
        for record in stored_records
        if isinstance(record.get("id"), (bytes, bytearray, memoryview))
    }


def _pick_records(records: Iterable[Mapping[str, Any]], allowed_attachment_values: list[str]) -> list[Any]:
    """Each record's credential once, keeping only attachments the hints allow."""

    picked: list[Any] = []
    seen_ids: set[bytes] = set()
    for record in records:
        cred_id = record.get("id")
        if not isinstance(cred_id, (bytes, bytearray, memoryview)):
            continue
        cred_id_bytes = bytes(cred_id)
        if cred_id_bytes in seen_ids:
            continue
        attachment_value = record.get("attachment")
        if allowed_attachment_values and attachment_value not in allowed_attachment_values:
            continue
        picked.append(record["data"])
        seen_ids.add(cred_id_bytes)
    return picked


def _pick_allowed(
    allow_credentials: list[Any], lookup: Mapping[bytes, Any], allowed_attachment_values: list[str]
) -> list[Any]:
    """The stored credentials the allow list names, once each, in its order."""

    picked: list[Any] = []
    seen_ids: set[bytes] = set()
    for allow_cred in allow_credentials:
        if not isinstance(allow_cred, dict) or allow_cred.get("type") != "public-key":
            continue

        cred_id = binary._extract_binary_value(allow_cred.get("id", ""))
        if isinstance(cred_id, str):
            try:
                cred_id = decode_hex(cred_id)
            except ValueError:
                continue

        if not isinstance(cred_id, (bytes, bytearray, memoryview)):
            continue

        cred_id_bytes = bytes(cred_id)
        if cred_id_bytes in seen_ids:
            continue

        record = lookup.get(cred_id_bytes)
        if record is None:
            continue

        attachment_value = record.get("attachment")
        if allowed_attachment_values and attachment_value not in allowed_attachment_values:
            continue

        picked.append(record["data"])
        seen_ids.add(cred_id_bytes)
    return picked


def select_begin_credentials(
    stored_records: list[dict[str, Any]], public_key: Mapping[str, Any], allowed_attachment_values: list[str]
) -> tuple[list[Any], list[dict[str, Any]], bool]:
    """The credentials to offer, the discoverable records, and whether only those may answer."""

    raw_allow_credentials = public_key.get("allowCredentials")
    allow_credentials: list[Any] = list(raw_allow_credentials) if isinstance(raw_allow_credentials, list) else []
    resident_key_only = not allow_credentials
    resident_records: list[dict[str, Any]] = []

    if allow_credentials:
        credentials_for_begin = _pick_allowed(
            allow_credentials, credential_lookup(stored_records), allowed_attachment_values
        )
        if not credentials_for_begin:
            credentials_for_begin = _pick_records(stored_records, allowed_attachment_values)
    else:
        resident_records = [record for record in stored_records if record.get("resident")]
        candidate_records = resident_records if resident_key_only and resident_records else stored_records
        credentials_for_begin = _pick_records(candidate_records, allowed_attachment_values)
    return credentials_for_begin, resident_records, resident_key_only


def begin_selection_error(
    credentials_for_begin: list[Any],
    resident_records: list[Any],
    resident_key_only: bool,
    allowed_attachment_values: list[str],
) -> Any:
    """The 404 when no credential qualifies to be offered, else ``None``."""

    if not credentials_for_begin and not resident_key_only:
        if allowed_attachment_values:
            return jsonify(
                {
                    "error": (
                        "No credentials matched the selected hints. "
                        "Please adjust your hints or select different credentials."
                    )
                }
            ), 404
        return jsonify(
            {"error": "No matching credentials found. Please register first."},
        ), 404

    if resident_key_only and resident_records and not credentials_for_begin:
        if allowed_attachment_values:
            return jsonify(
                {
                    "error": (
                        "No resident key credentials matched the selected hints. "
                        "Please adjust your hints or register a discoverable credential."
                    )
                }
            ), 404
        return jsonify(
            {
                "error": (
                    "No resident key credentials are available. "
                    "Please register a discoverable credential first."
                )
            }
        ), 404
    return None


def restore_complete_credentials(data: Mapping[str, Any]) -> tuple[list[dict[str, Any]], tuple[dict[str, Any], int] | None]:
    """The stored credentials for complete, or the failure payload and status to answer."""

    raw_credentials_input = credential_list_input(data)

    stored_records: list[dict[str, Any]] = []
    if isinstance(raw_credentials_input, list):
        stored_records, _serialized = parsing._parse_client_supplied_credentials(raw_credentials_input)

    if not stored_records:
        legacy_serialized = session.pop("advanced_auth_credentials", [])
        if legacy_serialized:
            stored_records, _serialized = parsing._parse_client_supplied_credentials(
                legacy_serialized,
            )

    if not stored_records:
        if isinstance(raw_credentials_input, list) and raw_credentials_input:
            session.pop("advanced_auth_credentials_meta", None)
            return [], (
                {
                    "error": (
                        "Stored credentials could not be restored from the browser session. "
                        "This often means the session cookie exceeded the browser size limit. "
                        "Please clear some saved credentials or restart the authentication flow and try again."
                    )
                },
                400,
            )
        session.pop("advanced_auth_credentials_meta", None)
        return [], ({"error": "No credentials found"}, 404)

    session.pop("advanced_auth_credentials_meta", None)
    return stored_records, None


def non_discoverable_error(
    resident_key_only: bool, selected_record: Mapping[str, Any] | None, credential_id_bytes: bytes | None
) -> dict[str, Any] | None:
    """The failure when a discoverable-only ceremony was answered by a non-discoverable credential."""

    if not (resident_key_only and selected_record is not None and not selected_record.get("resident")):
        return None
    response_payload = {
        "error": (
            "The credential used is not discoverable. Please register a resident key credential to "
            "authenticate without allowCredentials."
        )
    }
    if credential_id_bytes:
        response_payload["failedCredentialId"] = (
            encode_base64url(credential_id_bytes)
        )
    return response_payload
