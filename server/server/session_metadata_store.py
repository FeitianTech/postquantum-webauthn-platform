"""Session metadata storage helpers using local storage with GCS-compatible paths."""
from __future__ import annotations

import json
import os
import time
from typing import List, Optional

from .cloud_storage import (
    blob_exists,
    blob_updated_timestamp,
    build_blob_name,
    delete_blob,
    download_bytes,
    list_blob_names,
    upload_bytes,
)
from .config import app

__all__ = [
    "delete_file",
    "delete_session",
    "ensure_session",
    "file_exists",
    "file_mtime",
    "list_files",
    "list_sessions",
    "prune_session",
    "read_file",
    "resolve_last_access",
    "session_is_empty",
    "touch_last_access",
    "write_file",
]

# These prefixes match the GCS bucket structure
# Users can copy their GCS bucket contents directly to the storage folder
_USER_FOLDER_PREFIX = os.environ.get(
    "FIDO_SERVER_USER_FOLDER_PREFIX",
    os.environ.get("FIDO_SERVER_GCS_USER_FOLDER_PREFIX",
    os.environ.get("FIDO_SERVER_GCS_SESSION_METADATA_PREFIX", "user-data")),
)
_METADATA_SUBDIR = os.environ.get(
    "FIDO_SERVER_USER_METADATA_SUBDIR",
    os.environ.get("FIDO_SERVER_GCS_USER_METADATA_SUBDIR", "metadata"),
)
_LAST_ACCESS_BLOB = ".last-access"


def _user_root_prefix(session_id: str) -> str:
    """Build the root prefix for a user's data."""
    if not session_id:
        raise ValueError("Session identifier is required")
    cleaned = session_id.strip()
    if not cleaned:
        raise ValueError("Session identifier is required")
    return build_blob_name(cleaned, prefix=_USER_FOLDER_PREFIX)


def _metadata_prefix(session_id: str) -> str:
    """Build the prefix for a user's metadata files."""
    root = _user_root_prefix(session_id)
    return build_blob_name(_METADATA_SUBDIR, prefix=root)


def _last_access_blob(session_id: str) -> str:
    """Build the blob name for the last access marker."""
    root = _user_root_prefix(session_id)
    return build_blob_name(_LAST_ACCESS_BLOB, prefix=root)


def _session_blob(session_id: str, name: str) -> str:
    """Build the full blob name for a session metadata file."""
    prefix = _metadata_prefix(session_id)
    cleaned = name.strip("/")
    if not cleaned:
        raise ValueError("Invalid metadata filename")
    return f"{prefix}/{cleaned}" if prefix else cleaned


def _base_prefix() -> str:
    """Get the base prefix for all user data."""
    cleaned = (_USER_FOLDER_PREFIX or "").strip().strip("/")
    return f"{cleaned}/" if cleaned else ""


def ensure_session(session_id: str) -> None:
    """Ensure a session exists by touching its last access marker."""
    touch_last_access(session_id)


def list_sessions() -> List[str]:
    """List all session IDs that have stored data."""
    prefix = _base_prefix()
    seen = set()
    try:
        for blob_name in list_blob_names(prefix):
            remainder = blob_name[len(prefix):] if prefix else blob_name
            if not remainder:
                continue
            session_component = remainder.split("/", 1)[0].strip()
            if session_component:
                seen.add(session_component)
    except Exception as exc:
        app.logger.warning("Unable to list session metadata: %s", exc)
    return sorted(seen)


def touch_last_access(session_id: str, *, timestamp: Optional[float] = None) -> None:
    """Update the last access timestamp for a session."""
    marker_name = _last_access_blob(session_id)
    marker_value = json.dumps({"timestamp": timestamp or time.time()}).encode("utf-8")
    upload_bytes(marker_name, marker_value, content_type="application/json")


def resolve_last_access(session_id: str) -> Optional[float]:
    """Get the last access timestamp for a session."""
    marker_name = _last_access_blob(session_id)
    payload = download_bytes(marker_name)
    if payload:
        try:
            data = json.loads(payload.decode("utf-8"))
            if isinstance(data, dict) and isinstance(data.get("timestamp"), (int, float)):
                return float(data["timestamp"])
        except Exception:
            pass
    return blob_updated_timestamp(marker_name)


def list_files(session_id: str) -> List[str]:
    """List all metadata files for a session."""
    prefix = _metadata_prefix(session_id)
    if prefix:
        prefix = prefix + "/"
    names: List[str] = []
    try:
        for blob_name in list_blob_names(prefix):
            remainder = blob_name[len(prefix):] if prefix else blob_name
            if not remainder:
                continue
            if remainder.endswith("/"):
                continue
            if remainder == _LAST_ACCESS_BLOB:
                continue
            names.append(remainder)
    except Exception as exc:
        app.logger.warning("Unable to list metadata files for %s: %s", session_id, exc)
    return sorted(names)


def read_file(session_id: str, name: str) -> Optional[bytes]:
    """Read a metadata file for a session."""
    blob_name = _session_blob(session_id, name)
    return download_bytes(blob_name)


def write_file(session_id: str, name: str, data: bytes, *, content_type: Optional[str] = None) -> None:
    """Write a metadata file for a session."""
    blob_name = _session_blob(session_id, name)
    upload_bytes(blob_name, data, content_type=content_type)
    touch_last_access(session_id)


def delete_file(session_id: str, name: str, *, missing_ok: bool = True) -> None:
    """Delete a metadata file for a session."""
    blob_name = _session_blob(session_id, name)
    delete_blob(blob_name, missing_ok=missing_ok)
    touch_last_access(session_id)


def file_mtime(session_id: str, name: str) -> Optional[float]:
    """Get the modification time of a metadata file."""
    blob_name = _session_blob(session_id, name)
    return blob_updated_timestamp(blob_name)


def session_is_empty(session_id: str) -> bool:
    """Check if a session has no metadata files."""
    return not list_files(session_id)


def delete_session(session_id: str) -> None:
    """Delete all data for a session."""
    prefix = _user_root_prefix(session_id)
    if prefix:
        prefix = prefix + "/"
    to_delete: List[str] = []
    try:
        for blob_name in list_blob_names(prefix):
            to_delete.append(blob_name)
    except Exception as exc:
        app.logger.warning(
            "Unable to enumerate metadata for deletion under %s: %s", prefix, exc
        )
    for blob_name in to_delete:
        delete_blob(blob_name, missing_ok=True)


def prune_session(session_id: str) -> None:
    """Remove a session if it's empty."""
    if session_is_empty(session_id):
        delete_file(session_id, _LAST_ACCESS_BLOB, missing_ok=True)
        if session_is_empty(session_id):
            delete_session(session_id)


def file_exists(session_id: str, name: str) -> bool:
    """Check if a metadata file exists for a session."""
    blob_name = _session_blob(session_id, name)
    return blob_exists(blob_name)
