"""Shared storage/session helper utilities for backend storage modules."""

from __future__ import annotations

import os
from typing import Any, Callable, Optional


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