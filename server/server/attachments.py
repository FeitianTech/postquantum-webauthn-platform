"""Helpers for authenticator attachment hint handling."""
from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from typing import Any, Dict, List, Optional, Set

from .config import basepath
from .storage import extract_credential_data, readkey

__all__ = [
    "HINT_TO_ATTACHMENT_MAP",
    "build_credential_attachment_map",
    "derive_allowed_attachments_from_hints",
    "normalize_attachment",
    "normalize_attachment_list",
    "resolve_effective_attachments",
]


HINT_TO_ATTACHMENT_MAP: Dict[str, str] = {
    "security-key": "cross-platform",
    "hybrid": "cross-platform",
    "client-device": "platform",
}


def normalize_attachment(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized or None


def derive_allowed_attachments_from_hints(hints: Optional[Iterable[str]]) -> List[str]:
    allowed: List[str] = []
    if not hints:
        return allowed
    seen: Set[str] = set()
    for hint in hints:
        if not isinstance(hint, str):
            continue
        mapped = HINT_TO_ATTACHMENT_MAP.get(hint.strip().lower())
        if mapped and mapped not in seen:
            allowed.append(mapped)
            seen.add(mapped)
    return allowed


def normalize_attachment_list(raw_values: Any) -> List[str]:
    if isinstance(raw_values, Mapping):
        candidates: Iterable[Any] = raw_values.values()
    elif isinstance(raw_values, (str, bytes, bytearray)) or raw_values is None:
        return []
    elif isinstance(raw_values, Iterable):
        candidates = raw_values
    else:
        return []

    normalized: List[str] = []
    seen: Set[str] = set()
    for candidate in candidates:
        normalized_value = normalize_attachment(candidate)
        if normalized_value and normalized_value not in seen:
            normalized.append(normalized_value)
            seen.add(normalized_value)
    return normalized


def resolve_effective_attachments(
    hints: Iterable[str],
    requested_attachment: Optional[str] = None,
) -> List[str]:
    resolved = derive_allowed_attachments_from_hints(hints)
    if resolved:
        return resolved

    normalized_requested = normalize_attachment(requested_attachment)
    if normalized_requested:
        return [normalized_requested]

    return []


def build_credential_attachment_map() -> Dict[bytes, Optional[str]]:
    attachment_map: Dict[bytes, Optional[str]] = {}
    try:
        pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
    except Exception:
        return attachment_map

    for pkl_file in pkl_files:
        email = pkl_file.replace('_credential_data.pkl', '')
        try:
            user_creds = readkey(email)
        except Exception:
            continue

        for cred in user_creds:
            credential_data = extract_credential_data(cred)
            credential_id: Optional[bytes] = None
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

            attachment_value: Optional[str] = None
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
