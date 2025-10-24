"""High level helpers for storing per-session metadata in GCS."""
from __future__ import annotations

import json
import os
import time
from typing import Iterable, List, Optional

from .cloud_storage import (
    blob_exists,
    blob_updated_timestamp,
    build_blob_name,
    delete_blob,
    download_bytes,
    list_blob_names,
    upload_bytes,
)

_SESSION_PREFIX = os.environ.get("FIDO_SERVER_GCS_SESSION_METADATA_PREFIX", "session-metadata")
_LAST_ACCESS_BLOB = ".last-access"


def _session_prefix(session_id: str) -> str:
    if not session_id:
        raise ValueError("Session identifier is required")
    cleaned = session_id.strip()
    if not cleaned:
        raise ValueError("Session identifier is required")
    return build_blob_name(cleaned, prefix=_SESSION_PREFIX)


def _session_blob(session_id: str, name: str) -> str:
    prefix = _session_prefix(session_id)
    cleaned = name.strip("/")
    if not cleaned:
        raise ValueError("Invalid metadata filename")
    return f"{prefix}/{cleaned}" if prefix else cleaned


def _base_prefix() -> str:
    cleaned = (_SESSION_PREFIX or "").strip().strip("/")
    return f"{cleaned}/" if cleaned else ""


def ensure_session(session_id: str) -> None:
    touch_last_access(session_id)


def list_sessions() -> List[str]:
    prefix = _base_prefix()
    seen = set()
    for blob_name in list_blob_names(prefix):
        remainder = blob_name[len(prefix) :] if prefix else blob_name
        if not remainder:
            continue
        session_component = remainder.split("/", 1)[0].strip()
        if session_component:
            seen.add(session_component)
    return sorted(seen)


def touch_last_access(session_id: str, *, timestamp: Optional[float] = None) -> None:
    marker_name = _session_blob(session_id, _LAST_ACCESS_BLOB)
    marker_value = json.dumps({"timestamp": timestamp or time.time()}).encode("utf-8")
    upload_bytes(marker_name, marker_value, content_type="application/json")


def resolve_last_access(session_id: str) -> Optional[float]:
    marker_name = _session_blob(session_id, _LAST_ACCESS_BLOB)
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
    prefix = _session_prefix(session_id)
    if prefix:
        prefix = prefix + "/"
    names: List[str] = []
    for blob_name in list_blob_names(prefix):
        remainder = blob_name[len(prefix) :] if prefix else blob_name
        if not remainder:
            continue
        if remainder.endswith("/"):
            continue
        if remainder == _LAST_ACCESS_BLOB:
            continue
        names.append(remainder)
    return sorted(names)


def read_file(session_id: str, name: str) -> Optional[bytes]:
    blob_name = _session_blob(session_id, name)
    return download_bytes(blob_name)


def write_file(session_id: str, name: str, data: bytes, *, content_type: Optional[str] = None) -> None:
    blob_name = _session_blob(session_id, name)
    upload_bytes(blob_name, data, content_type=content_type)
    touch_last_access(session_id)


def delete_file(session_id: str, name: str, *, missing_ok: bool = True) -> None:
    blob_name = _session_blob(session_id, name)
    delete_blob(blob_name, missing_ok=missing_ok)
    touch_last_access(session_id)


def file_mtime(session_id: str, name: str) -> Optional[float]:
    blob_name = _session_blob(session_id, name)
    return blob_updated_timestamp(blob_name)


def session_is_empty(session_id: str) -> bool:
    files = list_files(session_id)
    return not files


def delete_session(session_id: str) -> None:
    prefix = _session_prefix(session_id)
    if prefix:
        prefix = prefix + "/"
    to_delete: List[str] = []
    for blob_name in list_blob_names(prefix):
        to_delete.append(blob_name)
    for blob_name in to_delete:
        delete_blob(blob_name, missing_ok=True)


def prune_session(session_id: str) -> None:
    if session_is_empty(session_id):
        delete_file(session_id, _LAST_ACCESS_BLOB, missing_ok=True)
        if session_is_empty(session_id):
            delete_session(session_id)


def file_exists(session_id: str, name: str) -> bool:
    blob_name = _session_blob(session_id, name)
    return blob_exists(blob_name)
