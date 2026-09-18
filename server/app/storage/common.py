"""Shared storage/session helper utilities for backend storage modules."""

from __future__ import annotations

import os
import posixpath
from collections.abc import Callable
from typing import Any

from werkzeug.security import safe_join

from .cloud import build_blob_name, normalise_blob_prefix

__all__ = [
    "assert_contained_blob_name",
    "build_session_root_prefix",
    "build_session_scoped_prefix",
    "normalize_nonempty_str",
    "resolve_contained_path",
    "resolve_metadata_session_id",
    "resolve_session_id",
    "using_gcs_backend",
    "validate_storage_component",
]

# Segments that must never appear in a path or object key built from caller
# supplied data. ``.`` and ``..`` traverse, the empty string collapses a key.
_RESERVED_SEGMENTS = frozenset({"", ".", ".."})
_PATH_SEPARATORS = ("/", "\\")


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


def resolve_session_id(session_id: str | None, fallback: Callable[[], str]) -> str:
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


def resolve_metadata_session_id(session_id: str | None = None) -> str:
    """Resolve a session id using metadata fallback with lazy import cycle-avoidance."""

    from ..webauthn.metadata import ensure_metadata_session_id

    return resolve_session_id(session_id, ensure_metadata_session_id)


def validate_storage_component(
    value: Any,
    *,
    type_error: str = "Storage identifier must be a string",
    empty_error: str = "Storage identifier is empty",
) -> str:
    """Return ``value`` stripped, after rejecting anything that can traverse.

    A credential name or session id is attacker supplied (it arrives as
    ``?email=`` or a cookie), and it is interpolated straight into a filesystem
    path and a GCS object key. Anything that could make the result denote a
    different directory -- a path separator, a ``..`` segment, a leading dot, a
    NUL or other control byte, or a drive-qualified/absolute path -- is
    rejected outright rather than sanitised, so a rejected request fails loudly
    instead of silently writing somewhere unexpected.
    """

    cleaned = normalize_nonempty_str(value, type_error=type_error, empty_error=empty_error)

    if "\x00" in cleaned:
        raise ValueError("Storage identifier contains a null byte")

    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in cleaned):
        raise ValueError("Storage identifier contains control characters")

    for separator in _PATH_SEPARATORS:
        if separator in cleaned:
            raise ValueError("Storage identifier contains a path separator")

    # ``os.altsep`` is ``/`` on Windows and ``None`` on POSIX; both real
    # separators are already covered above, this keeps the check honest if a
    # platform ever adds another one.
    for separator in (os.sep, os.altsep):
        if separator and separator in cleaned:
            raise ValueError("Storage identifier contains a path separator")

    if cleaned.startswith("."):
        raise ValueError("Storage identifier starts with a dot")

    if ".." in cleaned:
        raise ValueError("Storage identifier contains a parent directory reference")

    if os.path.isabs(cleaned) or posixpath.isabs(cleaned):
        raise ValueError("Storage identifier is an absolute path")

    return cleaned


def resolve_contained_path(
    root: str,
    *components: str,
    error: str = "Resolved path escapes the storage root",
) -> str:
    """Join ``components`` onto ``root`` and prove the result stays inside it.

    ``werkzeug.security.safe_join`` does the joining (the same helper the
    static asset route uses) and a ``realpath`` comparison is the second,
    independent check: it also catches a symlink planted inside the root that
    points outside it.
    """

    joined = safe_join(root, *components)
    if joined is None:
        raise ValueError(error)

    root_real = os.path.realpath(root)
    target_real = os.path.realpath(joined)
    if target_real != root_real and not target_real.startswith(root_real + os.sep):
        raise ValueError(error)

    return joined


def assert_contained_blob_name(
    blob_name: str,
    *,
    prefix: str | None = None,
    error: str = "Resolved object key escapes the storage prefix",
) -> str:
    """Return ``blob_name`` after proving it stays under ``prefix``.

    GCS keys are opaque strings, so the bucket will happily store
    ``user-data/../elsewhere``; anything that later mirrors the bucket onto a
    filesystem (gcsfuse, ``gsutil rsync``, a local cache) resolves it and the
    traversal becomes real. Treat a key the same way as a path.
    """

    if not isinstance(blob_name, str) or not blob_name:
        raise ValueError(error)

    if "\x00" in blob_name or "\\" in blob_name:
        raise ValueError(error)

    if any(segment in _RESERVED_SEGMENTS for segment in blob_name.split("/")):
        raise ValueError(error)

    normalised_prefix = normalise_blob_prefix(prefix)
    if normalised_prefix and not blob_name.startswith(normalised_prefix):
        raise ValueError(error)

    return blob_name
