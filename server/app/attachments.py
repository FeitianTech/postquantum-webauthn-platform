"""Helpers for authenticator attachment hint handling."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .storage.credentials import extract_credential_data, iter_credentials
from .webauthn.metadata import ensure_metadata_session_id

__all__ = [
    "HINT_TO_ATTACHMENT_MAP",
    "attachment_hint_violation",
    "build_credential_attachment_map",
    "derive_allowed_attachments_from_hints",
    "normalize_attachment",
    "normalize_attachment_list",
    "resolve_allowed_attachments",
    "resolve_effective_attachments",
]


HINT_TO_ATTACHMENT_MAP: dict[str, str] = {
    "security-key": "cross-platform",
    "hybrid": "cross-platform",
    "client-device": "platform",
}


def normalize_attachment(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized or None


def derive_allowed_attachments_from_hints(hints: Iterable[str] | None) -> list[str]:
    allowed: list[str] = []
    if not hints:
        return allowed
    seen: set[str] = set()
    for hint in hints:
        if not isinstance(hint, str):
            continue
        mapped = HINT_TO_ATTACHMENT_MAP.get(hint.strip().lower())
        if mapped and mapped not in seen:
            allowed.append(mapped)
            seen.add(mapped)
    return allowed


def normalize_attachment_list(raw_values: Any) -> list[str]:
    if isinstance(raw_values, Mapping):
        candidates: Iterable[Any] = raw_values.values()
    elif isinstance(raw_values, (str, bytes, bytearray)) or raw_values is None:
        return []
    elif isinstance(raw_values, Iterable):
        candidates = raw_values
    else:
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized_value = normalize_attachment(candidate)
        if normalized_value and normalized_value not in seen:
            normalized.append(normalized_value)
            seen.add(normalized_value)
    return normalized


def resolve_effective_attachments(
    hints: Iterable[str],
    requested_attachment: str | None = None,
) -> list[str]:
    resolved = derive_allowed_attachments_from_hints(hints)
    if resolved:
        return resolved

    normalized_requested = normalize_attachment(requested_attachment)
    if normalized_requested:
        return [normalized_requested]

    return []


def build_credential_attachment_map() -> dict[bytes, str | None]:
    """Each of the session's stored credentials, by id, and the attachment recorded for it.

    A store that cannot be read raises ``StorageReadError`` out of here rather
    than giving a map without some credentials: a missing id would read as
    "no attachment recorded", and a hint check would pass on it. A copy that
    does not decode is left out; the store logs it.
    """

    attachment_map: dict[bytes, str | None] = {}
    metadata_session_id = ensure_metadata_session_id()
    for email, user_creds in iter_credentials(session_id=metadata_session_id):
        for cred in user_creds:
            credential_data = extract_credential_data(cred)
            credential_id: bytes | None = None
            if isinstance(credential_data, Mapping):
                raw_id = credential_data.get('credential_id')
                if isinstance(raw_id, (bytes, bytearray, memoryview)):
                    credential_id = bytes(raw_id)
            else:
                raw_id = getattr(credential_data, 'credential_id', None)
                if isinstance(raw_id, (bytes, bytearray, memoryview)):
                    credential_id = bytes(raw_id)

            if credential_id is None:
                continue

            attachment_value: str | None = None
            if isinstance(cred, Mapping):
                attachment_value = normalize_attachment(
                    cred.get('authenticator_attachment')
                    or cred.get('authenticatorAttachment')
                )
                if attachment_value is None:
                    properties = cred.get('properties')
                    if isinstance(properties, Mapping):
                        attachment_value = normalize_attachment(
                            properties.get('authenticatorAttachment')
                            or properties.get('authenticator_attachment')
                        )

            attachment_map[credential_id] = attachment_value

    return attachment_map


def resolve_allowed_attachments(session_marker: Any, request_allowed: list[str]) -> list[str]:
    """The attachments a ceremony's hints allow: those recorded at begin, else the request's own."""

    if session_marker is None:
        allowed = request_allowed
    else:
        allowed = normalize_attachment_list(session_marker)
    if not allowed:
        allowed = request_allowed
    return allowed


def attachment_hint_violation(allowed: list[str], response_attachment: str | None) -> str | None:
    """Why the attachment a response reports breaks the allowed attachments, or ``None``."""

    if not allowed:
        return None
    if response_attachment is None:
        return "Authenticator attachment could not be determined to enforce selected hints."
    if response_attachment not in allowed:
        return "Authenticator attachment is not permitted by the selected hints."
    return None
