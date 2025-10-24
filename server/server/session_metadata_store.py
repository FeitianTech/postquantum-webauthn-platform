"""Session metadata storage helpers backed by pluggable storage."""
from __future__ import annotations

import json
import os
import shutil
import time
from datetime import timedelta
from typing import List, Optional

from .cloud_storage import (
    blob_exists,
    blob_updated_timestamp,
    build_blob_name,
    delete_blob,
    download_bytes,
    gcs_enabled,
    list_blob_names,
    upload_bytes,
)
from .config import SESSION_METADATA_DIR, app

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

_SESSION_PREFIX = os.environ.get("FIDO_SERVER_GCS_SESSION_METADATA_PREFIX", "session-metadata")
_LAST_ACCESS_BLOB = ".last-access"

_LOCAL_INACTIVE_AGE = timedelta(days=7)
_LOCAL_CLEANUP_INTERVAL = timedelta(hours=6)
_local_last_cleanup: float = 0.0


def _using_gcs() -> bool:
    return gcs_enabled() and bool(os.environ.get("FIDO_SERVER_GCS_BUCKET"))


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


def _normalise_local_session_id(session_id: str) -> str:
    if not isinstance(session_id, str):
        raise ValueError("Session identifier is required")
    trimmed = session_id.strip()
    if not trimmed or trimmed.startswith("."):
        raise ValueError("Session identifier is invalid")
    for separator in (os.sep, os.altsep):
        if separator and separator in trimmed:
            raise ValueError("Session identifier is invalid")
    return trimmed


def _local_session_directory(session_id: str, *, create: bool = False) -> Optional[str]:
    try:
        normalised = _normalise_local_session_id(session_id)
    except ValueError:
        return None

    directory = os.path.join(SESSION_METADATA_DIR, normalised)

    if create:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:
            app.logger.error("Failed to prepare session metadata directory %s: %s", directory, exc)
            raise
        _local_touch_last_access(directory)

    return directory


def _local_touch_last_access(directory: str) -> None:
    marker_path = os.path.join(directory, _LAST_ACCESS_BLOB)
    try:
        os.makedirs(os.path.dirname(marker_path), exist_ok=True)
        with open(marker_path, "a", encoding="utf-8"):
            os.utime(marker_path, None)
    except OSError:
        pass


def _local_resolve_last_access(directory: str) -> Optional[float]:
    marker_path = os.path.join(directory, _LAST_ACCESS_BLOB)
    try:
        return os.path.getmtime(marker_path)
    except OSError:
        pass

    latest: Optional[float] = None
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                try:
                    candidate = entry.stat(follow_symlinks=False).st_mtime
                except OSError:
                    continue
                if latest is None or candidate > latest:
                    latest = candidate
    except OSError:
        return None

    if latest is not None:
        return latest

    try:
        return os.path.getmtime(directory)
    except OSError:
        return None


def _local_maybe_cleanup(now: Optional[float] = None) -> None:
    global _local_last_cleanup

    current_time = now or time.time()
    if current_time - _local_last_cleanup < _LOCAL_CLEANUP_INTERVAL.total_seconds():
        return

    _local_last_cleanup = current_time
    cutoff = current_time - _LOCAL_INACTIVE_AGE.total_seconds()

    try:
        entries = os.listdir(SESSION_METADATA_DIR)
    except OSError:
        return

    for entry in entries:
        if entry.startswith("."):
            continue

        directory = os.path.join(SESSION_METADATA_DIR, entry)
        if not os.path.isdir(directory):
            continue

        last_access = _local_resolve_last_access(directory)
        if last_access is None or last_access >= cutoff:
            continue

        try:
            shutil.rmtree(directory)
        except OSError as exc:
            app.logger.warning("Failed to remove inactive metadata session %s: %s", directory, exc)


def _local_note_activity(session_id: str) -> None:
    directory = _local_session_directory(session_id)
    if directory and os.path.isdir(directory):
        _local_touch_last_access(directory)
    _local_maybe_cleanup()


def ensure_session(session_id: str) -> None:
    if _using_gcs():
        touch_last_access(session_id)
    else:
        _local_session_directory(session_id, create=True)
        _local_maybe_cleanup()


def list_sessions() -> List[str]:
    if _using_gcs():
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

    try:
        entries = os.listdir(SESSION_METADATA_DIR)
    except OSError:
        return []

    sessions: List[str] = []
    for entry in entries:
        path = os.path.join(SESSION_METADATA_DIR, entry)
        if os.path.isdir(path) and not entry.startswith("."):
            sessions.append(entry)
    return sorted(sessions)


def touch_last_access(session_id: str, *, timestamp: Optional[float] = None) -> None:
    if _using_gcs():
        marker_name = _session_blob(session_id, _LAST_ACCESS_BLOB)
        marker_value = json.dumps({"timestamp": timestamp or time.time()}).encode("utf-8")
        upload_bytes(marker_name, marker_value, content_type="application/json")
        return

    directory = _local_session_directory(session_id, create=True)
    if directory is None:
        return
    if timestamp:
        marker_path = os.path.join(directory, _LAST_ACCESS_BLOB)
        try:
            os.makedirs(os.path.dirname(marker_path), exist_ok=True)
            with open(marker_path, "a", encoding="utf-8"):
                os.utime(marker_path, (timestamp, timestamp))
        except OSError:
            pass
    else:
        _local_touch_last_access(directory)


def resolve_last_access(session_id: str) -> Optional[float]:
    if _using_gcs():
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

    directory = _local_session_directory(session_id)
    if not directory:
        return None
    return _local_resolve_last_access(directory)


def list_files(session_id: str) -> List[str]:
    if _using_gcs():
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

    directory = _local_session_directory(session_id)
    if not directory:
        return []

    try:
        entries = os.listdir(directory)
    except OSError:
        return []

    names: List[str] = []
    for entry in entries:
        if entry == _LAST_ACCESS_BLOB or entry.startswith("."):
            continue
        path = os.path.join(directory, entry)
        if os.path.isfile(path):
            names.append(entry)
    return sorted(names)


def read_file(session_id: str, name: str) -> Optional[bytes]:
    if _using_gcs():
        blob_name = _session_blob(session_id, name)
        return download_bytes(blob_name)

    directory = _local_session_directory(session_id)
    if not directory:
        return None

    path = os.path.join(directory, name)
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def write_file(session_id: str, name: str, data: bytes, *, content_type: Optional[str] = None) -> None:
    if _using_gcs():
        blob_name = _session_blob(session_id, name)
        upload_bytes(blob_name, data, content_type=content_type)
        touch_last_access(session_id)
        return

    directory = _local_session_directory(session_id, create=True)
    if not directory:
        raise ValueError("Invalid session identifier")

    path = os.path.join(directory, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    _local_note_activity(session_id)


def delete_file(session_id: str, name: str, *, missing_ok: bool = True) -> None:
    if _using_gcs():
        blob_name = _session_blob(session_id, name)
        delete_blob(blob_name, missing_ok=missing_ok)
        touch_last_access(session_id)
        return

    directory = _local_session_directory(session_id)
    if not directory:
        return

    path = os.path.join(directory, name)
    try:
        os.remove(path)
    except FileNotFoundError:
        if not missing_ok:
            raise
    except OSError:
        if not missing_ok:
            raise
    _local_note_activity(session_id)


def file_mtime(session_id: str, name: str) -> Optional[float]:
    if _using_gcs():
        blob_name = _session_blob(session_id, name)
        return blob_updated_timestamp(blob_name)

    directory = _local_session_directory(session_id)
    if not directory:
        return None

    path = os.path.join(directory, name)
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def session_is_empty(session_id: str) -> bool:
    return not list_files(session_id)


def delete_session(session_id: str) -> None:
    if _using_gcs():
        prefix = _session_prefix(session_id)
        if prefix:
            prefix = prefix + "/"
        to_delete: List[str] = []
        for blob_name in list_blob_names(prefix):
            to_delete.append(blob_name)
        for blob_name in to_delete:
            delete_blob(blob_name, missing_ok=True)
        return

    directory = _local_session_directory(session_id)
    if not directory:
        return

    try:
        shutil.rmtree(directory)
    except OSError as exc:
        app.logger.warning("Failed to remove metadata session %s: %s", directory, exc)


def prune_session(session_id: str) -> None:
    if session_is_empty(session_id):
        delete_file(session_id, _LAST_ACCESS_BLOB, missing_ok=True)
        if session_is_empty(session_id):
            delete_session(session_id)


def file_exists(session_id: str, name: str) -> bool:
    if _using_gcs():
        blob_name = _session_blob(session_id, name)
        return blob_exists(blob_name)

    directory = _local_session_directory(session_id)
    if not directory:
        return False
    return os.path.isfile(os.path.join(directory, name))


# Ensure the base directory exists for local development environments.
os.makedirs(SESSION_METADATA_DIR, exist_ok=True)
