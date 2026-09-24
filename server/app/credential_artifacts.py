"""Server-side storage for advanced credential artifacts.

An artifact is kept per metadata session: on GCS under
``user-data/<session>/credential-artifacts/``, locally under
``<artifact dir>/<session>/``, each named by the SHA-256 of its storage id.
"""

from __future__ import annotations

import contextlib
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
    download_bytes_with_generation,
    gcs_enabled,
    upload_bytes,
    upload_bytes_if_generation,
)
from .storage.common import (
    assert_contained_blob_name,
    build_session_root_prefix,
    build_session_scoped_prefix,
    file_lock,
    resolve_contained_path,
    resolve_metadata_session_id,
    using_gcs_backend,
    validate_storage_component,
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
# making every artifact operation in the process wait on network I/O. They keep
# threads apart; across processes a local record's writers hold an flock on its
# ``.lock`` file, and on GCS a merge is conditional on the generation it read.
_LOCK_STRIPES = tuple(threading.RLock() for _ in range(64))
# A merge that loses re-reads and merges into the winner's record. Each other
# writer wins at most once while it waits, so eight attempts cover eight at once.
_MERGE_ATTEMPTS = 8


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


def _session_directory(session_id: str) -> str:
    return resolve_contained_path(_ARTIFACT_DIR, validate_storage_component(session_id))


def _artifact_path(storage_id: str, session_id: str) -> str:
    # ``_artifact_filename`` is a SHA-256 digest, so it cannot traverse today.
    # The containment check keeps that true if the naming scheme ever changes;
    # the session id, which comes from the session, is validated as a name.
    return resolve_contained_path(_session_directory(session_id), _artifact_filename(storage_id))


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


def _ensure_directory(session_id: str) -> None:
    os.makedirs(_session_directory(session_id), exist_ok=True)


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

    return _read_file(_artifact_path(storage_id, session_id))


def _encode_record(record: dict[str, Any]) -> bytes:
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _decode_record(payload: bytes | None) -> dict[str, Any] | None:
    if not payload:
        return None
    try:
        return json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _write_record(storage_id: str, session_id: str, record: dict[str, Any]) -> None:
    if _using_gcs():
        blob_name = _artifact_blob(storage_id, session_id)
        upload_bytes(blob_name, _encode_record(record), content_type="application/json")
        return

    _ensure_directory(session_id)
    _write_file(_artifact_path(storage_id, session_id), record)


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

    try:
        _remove_locked(_artifact_path(storage_id, session_id))
    except FileNotFoundError:
        return False
    except OSError:
        return False
    return True


def _remove_locked(path: str) -> None:
    """Remove a local record under the lock its writers hold; no lock file for no record."""

    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with file_lock(path):
        os.remove(path)


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
        if _using_gcs() and merge:
            return _merge_on_gcs(normalised, resolved_session, payload, timestamp)
        with contextlib.ExitStack() as held:
            if not _using_gcs():
                try:
                    _ensure_directory(resolved_session)
                    held.enter_context(file_lock(_artifact_path(normalised, resolved_session)))
                except OSError:
                    return False
            existing = _read_record(normalised, resolved_session) if merge else None
            record = _updated_record(normalised, existing, payload, merge=merge, timestamp=timestamp)
            try:
                _write_record(normalised, resolved_session, record)
            except Exception:
                return False

    return True


def _updated_record(
    storage_id: str, existing: Any, payload: dict[str, Any], *, merge: bool, timestamp: float
) -> dict[str, Any]:
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

    return {
        "storageId": storage_id,
        "createdAt": created_at or timestamp,
        "updatedAt": timestamp,
        "payload": base_payload,
    }


def _merge_on_gcs(storage_id: str, session_id: str, payload: dict[str, Any], timestamp: float) -> bool:
    """Read-merge-write conditional on the generation read; a lost race merges again."""

    blob_name = _artifact_blob(storage_id, session_id)
    for _attempt in range(_MERGE_ATTEMPTS):
        try:
            stored, generation = download_bytes_with_generation(blob_name)
        except Exception:
            # Merging into a record that could not be read would overwrite it.
            return False
        record = _updated_record(storage_id, _decode_record(stored), payload, merge=True, timestamp=timestamp)
        try:
            if upload_bytes_if_generation(
                blob_name, _encode_record(record), generation=generation, content_type="application/json"
            ):
                return True
        except Exception:
            # The write may have landed with only its reply lost: what is stored now says.
            return _merge_is_stored(blob_name, payload)
    return False


def _merge_is_stored(blob_name: str, update: dict[str, Any]) -> bool:
    """Whether the stored record holds every value ``update`` merges in; ``False`` if it cannot be read."""

    try:
        stored, _generation = download_bytes_with_generation(blob_name)
    except Exception:
        return False
    record = _decode_record(stored)
    return isinstance(record, dict) and _holds(record.get("payload"), update)


def _holds(payload: Any, update: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(payload.get(key), dict):
            if not _holds(payload[key], value):
                return False
        elif key not in payload or payload[key] != value:
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

        try:
            _remove_locked(_artifact_path(normalised, resolved_session))
        except FileNotFoundError:
            return "absent"
        except OSError:
            return "failed"

    return "deleted"
