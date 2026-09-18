"""Server-side storage for advanced credential artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any

from .config import _SERVER_RUNTIME_ROOT
from .storage.cloud import (
    blob_exists,
    build_blob_name,
    delete_blob,
    download_bytes,
    gcs_enabled,
    upload_bytes,
)
from .storage.common import (
    assert_contained_blob_name,
    build_session_root_prefix,
    build_session_scoped_prefix,
    resolve_contained_path,
    resolve_metadata_session_id,
    using_gcs_backend,
)

__all__ = [
    "store_credential_artifact",
    "load_credential_artifact",
    "delete_credential_artifact",
    "delete_credential_artifact_with_status",
]


_ARTIFACT_DIR = os.environ.get(
    "FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR",
    os.path.join(str(_SERVER_RUNTIME_ROOT), "credential-artifacts"),
)
_USER_FOLDER_PREFIX = os.environ.get(
    "FIDO_SERVER_GCS_USER_FOLDER_PREFIX",
    os.environ.get("FIDO_SERVER_GCS_CREDENTIAL_ARTIFACT_PREFIX", "user-data"),
)
_ARTIFACT_SUBDIR = os.environ.get(
    "FIDO_SERVER_GCS_USER_ARTIFACT_SUBDIR",
    os.environ.get("FIDO_SERVER_GCS_CREDENTIAL_ARTIFACT_PREFIX", "credential-artifacts"),
)
# Striped per-key locks: serialise read-merge-write for one artifact without
# making every artifact operation in the process wait on network I/O.
_LOCK_STRIPES = tuple(threading.RLock() for _ in range(64))


def _lock_for(storage_id: str, session_id: str) -> threading.RLock:
    digest = hashlib.sha256(f"{session_id}\0{storage_id}".encode("utf-8")).digest()
    return _LOCK_STRIPES[digest[0] % len(_LOCK_STRIPES)]


def _normalise_storage_id(storage_id: Any) -> str | None:
    if not isinstance(storage_id, str):
        return None

    trimmed = storage_id.strip()
    if not trimmed:
        return None

    return trimmed


def _artifact_path(storage_id: str) -> str:
    # ``_artifact_filename`` is a SHA-256 digest, so it cannot traverse today.
    # The containment check keeps that true if the naming scheme ever changes.
    return resolve_contained_path(_ARTIFACT_DIR, _artifact_filename(storage_id))


def _artifact_filename(storage_id: str) -> str:
    digest = hashlib.sha256(storage_id.encode("utf-8")).hexdigest()
    return f"{digest}.json"


def _user_root_prefix(session_id: str) -> str:
    return build_session_root_prefix(
        session_id,
        user_folder_prefix=_USER_FOLDER_PREFIX,
        type_error="Session identifier must be a string",
        empty_error="Session identifier must be a string",
    )


def _artifact_prefix(session_id: str) -> str:
    return build_session_scoped_prefix(
        session_id,
        user_folder_prefix=_USER_FOLDER_PREFIX,
        subdir=_ARTIFACT_SUBDIR,
        type_error="Session identifier must be a string",
        empty_error="Session identifier must be a string",
    )


def _artifact_blob(storage_id: str, session_id: str) -> str:
    filename = _artifact_filename(storage_id)
    prefix = _artifact_prefix(session_id)
    return assert_contained_blob_name(build_blob_name(filename, prefix=prefix), prefix=prefix)


def _using_gcs() -> bool:
    return using_gcs_backend(gcs_enabled)


def _ensure_directory() -> None:
    os.makedirs(_ARTIFACT_DIR, exist_ok=True)


def _read_file(path: str) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None


def _write_file(path: str, payload: dict[str, Any]) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp_path, path)


def _resolve_session_id(session_id: str | None = None) -> str:
    return resolve_metadata_session_id(session_id)


def _read_record(storage_id: str, session_id: str) -> dict[str, Any] | None:
    if _using_gcs():
        blob_name = _artifact_blob(storage_id, session_id)
        try:
            payload = download_bytes(blob_name)
        except Exception:
            return None
        if not payload:
            return None
        try:
            return json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    return _read_file(_artifact_path(storage_id))


def _write_record(storage_id: str, session_id: str, record: dict[str, Any]) -> None:
    if _using_gcs():
        blob_name = _artifact_blob(storage_id, session_id)
        payload = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        upload_bytes(blob_name, payload, content_type="application/json")
        return

    _ensure_directory()
    _write_file(_artifact_path(storage_id), record)


def _delete_record(storage_id: str, session_id: str) -> bool:
    if _using_gcs():
        blob_name = _artifact_blob(storage_id, session_id)
        try:
            existed = blob_exists(blob_name)
        except Exception:
            existed = False
        try:
            delete_blob(blob_name, missing_ok=True)
        except Exception:
            return False
        return existed

    path = _artifact_path(storage_id)
    try:
        os.remove(path)
    except FileNotFoundError:
        return False
    except OSError:
        return False
    return True


def load_credential_artifact(
    storage_id: Any,
    *,
    session_id: str | None = None,
) -> dict[str, Any] | None:
    """Return the stored artifact payload for ``storage_id`` if available."""

    normalised = _normalise_storage_id(storage_id)
    if not normalised:
        return None

    resolved_session = _resolve_session_id(session_id)

    with _lock_for(normalised, resolved_session):
        stored = _read_record(normalised, resolved_session)

    if not stored or not isinstance(stored, dict):
        return None

    payload = stored.get("payload")
    if isinstance(payload, dict):
        return payload

    return None


def _merge_payload(base: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    for key, value in update.items():
        if (
            isinstance(value, dict)
            and isinstance(base.get(key), dict)
        ):
            base[key] = _merge_payload(dict(base[key]), value)
        else:
            base[key] = value
    return base


def store_credential_artifact(
    storage_id: Any,
    payload: dict[str, Any],
    *,
    merge: bool = False,
    session_id: str | None = None,
) -> bool:
    """Persist ``payload`` for ``storage_id``.

    When ``merge`` is true, existing payload keys are shallowly merged with the
    provided payload. Returns ``True`` when the artifact was stored.
    """

    normalised = _normalise_storage_id(storage_id)
    if not normalised or not isinstance(payload, dict):
        return False

    timestamp = time.time()

    resolved_session = _resolve_session_id(session_id)

    with _lock_for(normalised, resolved_session):
        existing = _read_record(normalised, resolved_session) if merge else None
        base_payload: dict[str, Any]
        if merge and existing and isinstance(existing, dict):
            current_payload = existing.get("payload")
            if isinstance(current_payload, dict):
                base_payload = _merge_payload(dict(current_payload), payload)
            else:
                base_payload = dict(payload)
            created_at = existing.get("createdAt")
        else:
            base_payload = dict(payload)
            created_at = None

        record = {
            "storageId": normalised,
            "createdAt": created_at or timestamp,
            "updatedAt": timestamp,
            "payload": base_payload,
        }

        try:
            _write_record(normalised, resolved_session, record)
        except Exception:
            return False

    return True


def delete_credential_artifact(storage_id: Any, *, session_id: str | None = None) -> bool:
    """Delete the stored artifact for ``storage_id`` if it exists."""

    normalised = _normalise_storage_id(storage_id)
    if not normalised:
        return False

    resolved_session = _resolve_session_id(session_id)

    with _lock_for(normalised, resolved_session):
        return _delete_record(normalised, resolved_session)


def delete_credential_artifact_with_status(
    storage_id: Any,
    *,
    session_id: str | None = None,
) -> str:
    """Delete the stored artifact for ``storage_id`` and return a status string.

    Returns one of:
    - ``"deleted"`` when the artifact existed and was deleted.
    - ``"absent"`` when the artifact was already missing.
    - ``"failed"`` when the deletion could not be confirmed.
    """

    normalised = _normalise_storage_id(storage_id)
    if not normalised:
        return "failed"

    resolved_session = _resolve_session_id(session_id)

    with _lock_for(normalised, resolved_session):
        if _using_gcs():
            blob_name = _artifact_blob(normalised, resolved_session)
            try:
                existed = blob_exists(blob_name)
            except Exception:
                return "failed"

            try:
                delete_blob(blob_name, missing_ok=True)
            except Exception:
                return "failed"

            return "deleted" if existed else "absent"

        path = _artifact_path(normalised)
        try:
            os.remove(path)
        except FileNotFoundError:
            return "absent"
        except OSError:
            return "failed"

    return "deleted"
