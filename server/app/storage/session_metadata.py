"""Session metadata storage helpers backed by pluggable storage."""
from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time
from datetime import timedelta

from ..config import SESSION_METADATA_DIR
from .cloud import (
    blob_exists,
    blob_updated_timestamp,
    build_blob_name,
    delete_blob,
    download_bytes,
    gcs_enabled,
    list_blob_names,
    list_prefixes,
    upload_bytes,
)
from .common import (
    build_session_root_prefix,
    build_session_scoped_prefix,
    using_gcs_backend,
)

logger = logging.getLogger(__name__)

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

_USER_FOLDER_PREFIX = os.environ.get(
    "FIDO_SERVER_GCS_USER_FOLDER_PREFIX",
    os.environ.get("FIDO_SERVER_GCS_SESSION_METADATA_PREFIX", "user-data"),
)
_METADATA_SUBDIR = os.environ.get(
    "FIDO_SERVER_GCS_USER_METADATA_SUBDIR",
    "metadata",
)
_LAST_ACCESS_BLOB = ".last-access"

_LOCAL_INACTIVE_AGE = timedelta(days=14)
_LOCAL_CLEANUP_INTERVAL = timedelta(hours=6)
_local_last_cleanup: float = 0.0
_local_cleanup_lock = threading.Lock()


def _using_gcs() -> bool:
    return using_gcs_backend(gcs_enabled)


def _user_root_prefix(session_id: str) -> str:
    return build_session_root_prefix(
        session_id,
        user_folder_prefix=_USER_FOLDER_PREFIX,
        type_error="Session identifier is required",
        empty_error="Session identifier is required",
    )


def _metadata_prefix(session_id: str) -> str:
    return build_session_scoped_prefix(
        session_id,
        user_folder_prefix=_USER_FOLDER_PREFIX,
        subdir=_METADATA_SUBDIR,
        type_error="Session identifier is required",
        empty_error="Session identifier is required",
    )


def _last_access_blob(session_id: str) -> str:
    root = _user_root_prefix(session_id)
    return build_blob_name(_LAST_ACCESS_BLOB, prefix=root)


def _session_blob(session_id: str, name: str) -> str:
    prefix = _metadata_prefix(session_id)
    cleaned = name.strip("/")
    if not cleaned:
        raise ValueError("Invalid metadata filename")
    return f"{prefix}/{cleaned}" if prefix else cleaned


def _base_prefix() -> str:
    cleaned = (_USER_FOLDER_PREFIX or "").strip().strip("/")
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


def _local_session_directory(session_id: str, *, create: bool = False) -> str | None:
    try:
        normalised = _normalise_local_session_id(session_id)
    except ValueError:
        return None

    directory = os.path.join(SESSION_METADATA_DIR, normalised)

    if create:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:
            logger.error("Failed to prepare session metadata directory %s: %s", directory, exc)
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


def _local_resolve_last_access(directory: str) -> float | None:
    marker_path = os.path.join(directory, _LAST_ACCESS_BLOB)
    try:
        return os.path.getmtime(marker_path)
    except OSError:
        pass

    latest: float | None = None
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


def _local_maybe_cleanup(now: float | None = None) -> None:
    global _local_last_cleanup

    current_time = now or time.time()
    with _local_cleanup_lock:
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
            logger.warning("Failed to remove inactive metadata session %s: %s", directory, exc)


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


def list_sessions() -> list[str]:
    if _using_gcs():
        prefix = _base_prefix()
        seen = set()
        try:
            # One entry per session folder, not every object in every session.
            # A flat object beside the folders (a legacy credential copy) is no session.
            for folder in list_prefixes(prefix):
                session_component = folder[len(prefix) :].strip("/").strip()
                if session_component:
                    seen.add(session_component)
        except Exception as exc:  # pragma: no cover - depends on storage backend
            logger.warning("Unable to list session metadata blobs: %s", exc)
        return sorted(seen)

    try:
        entries = os.listdir(SESSION_METADATA_DIR)
    except OSError:
        return []

    sessions: list[str] = []
    for entry in entries:
        path = os.path.join(SESSION_METADATA_DIR, entry)
        if os.path.isdir(path) and not entry.startswith("."):
            sessions.append(entry)
    return sorted(sessions)


def touch_last_access(session_id: str, *, timestamp: float | None = None) -> None:
    if _using_gcs():
        marker_name = _last_access_blob(session_id)
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


def resolve_last_access(session_id: str) -> float | None:
    if _using_gcs():
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

    directory = _local_session_directory(session_id)
    if not directory:
        return None
    return _local_resolve_last_access(directory)


def list_files(session_id: str) -> list[str]:
    if _using_gcs():
        prefix = _metadata_prefix(session_id)
        if prefix:
            prefix = prefix + "/"
        names: list[str] = []
        try:
            for blob_name in list_blob_names(prefix):
                remainder = blob_name[len(prefix) :] if prefix else blob_name
                if not remainder:
                    continue
                if remainder.endswith("/"):
                    continue
                if remainder == _LAST_ACCESS_BLOB:
                    continue
                names.append(remainder)
        except Exception as exc:  # pragma: no cover - depends on storage backend
            logger.warning("Unable to list metadata files for %s: %s", session_id, exc)
        return sorted(names)

    directory = _local_session_directory(session_id)
    if not directory:
        return []

    try:
        entries = os.listdir(directory)
    except OSError:
        return []

    names: list[str] = []
    for entry in entries:
        if entry == _LAST_ACCESS_BLOB or entry.startswith("."):
            continue
        path = os.path.join(directory, entry)
        if os.path.isfile(path):
            names.append(entry)
    return sorted(names)


def read_file(session_id: str, name: str) -> bytes | None:
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


def write_file(session_id: str, name: str, data: bytes, *, content_type: str | None = None) -> None:
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


def file_mtime(session_id: str, name: str) -> float | None:
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
        prefix = _user_root_prefix(session_id)
        if prefix:
            prefix = prefix + "/"
        to_delete: list[str] = []
        try:
            for blob_name in list_blob_names(prefix):
                to_delete.append(blob_name)
        except Exception as exc:  # pragma: no cover - depends on storage backend
            logger.warning(
                "Unable to enumerate metadata for deletion under %s: %s", prefix, exc
            )
        for blob_name in to_delete:
            delete_blob(blob_name, missing_ok=True)
        return

    directory = _local_session_directory(session_id)
    if not directory:
        return

    try:
        shutil.rmtree(directory)
    except OSError as exc:
        logger.warning("Failed to remove metadata session %s: %s", directory, exc)


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
