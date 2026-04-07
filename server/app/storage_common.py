"""Shared storage/session helper utilities for backend storage modules."""

from __future__ import annotations

import os
from typing import Any, Callable, Optional

from .cloud_storage import build_blob_name


def using_gcs_backend(is_enabled: Callable[[], bool]) -> bool:
    """Return ``True`` when cloud storage is enabled and bucket-configured."""

    return bool(is_enabled()) and bool(os.environ.get("FIDO_SERVER_GCS_BUCKET"))


def normalize_nonempty_str(value: Any, *, type_error: str, empty_error: str) -> str:
    """Validate ``value`` is a non-empty string and return its stripped form."""

    if not isinstance(value, str):
        raise ValueError(type_error)
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(empty_error)
    return cleaned


def resolve_session_id(session_id: Optional[str], fallback: Callable[[], str]) -> str:
    """Resolve an explicit session id or fall back to ``fallback`` when absent."""

    if isinstance(session_id, str):
        trimmed = session_id.strip()
        if trimmed:
            return trimmed
    return fallback()


def build_session_root_prefix(
    session_id: Any,
    *,
    user_folder_prefix: str,
    type_error: str = "Session identifier must be a string",
    empty_error: str = "Session identifier is empty",
) -> str:
    """Build a session root blob prefix for a module-specific user folder."""

    cleaned = normalize_nonempty_str(
        session_id,
        type_error=type_error,
        empty_error=empty_error,
    )
    return build_blob_name(cleaned, prefix=user_folder_prefix)


def build_session_scoped_prefix(
    session_id: Any,
    *,
    user_folder_prefix: str,
    subdir: str,
    type_error: str = "Session identifier must be a string",
    empty_error: str = "Session identifier is empty",
) -> str:
    """Build a ``<user-folder>/<session>/<subdir>`` blob prefix."""

    root = build_session_root_prefix(
        session_id,
        user_folder_prefix=user_folder_prefix,
        type_error=type_error,
        empty_error=empty_error,
    )
    return build_blob_name(subdir, prefix=root)


def resolve_metadata_session_id(session_id: Optional[str] = None) -> str:
    """Resolve a session id using metadata fallback with lazy import cycle-avoidance."""

    from .metadata import ensure_metadata_session_id

    return resolve_session_id(session_id, ensure_metadata_session_id)
