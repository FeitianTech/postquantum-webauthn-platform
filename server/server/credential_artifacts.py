"""Server-side storage for advanced credential artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, Optional

from .cloud_storage import (
    blob_exists,
    build_blob_name,
    delete_blob,
    download_bytes,
    gcs_enabled,
    upload_bytes,
)
from .config import basepath

__all__ = [
    "store_credential_artifact",
    "load_credential_artifact",
    "delete_credential_artifact",
]


_ARTIFACT_DIR = os.path.join(basepath, "static", "credential-artifacts")
_ARTIFACT_PREFIX = os.environ.get("FIDO_SERVER_GCS_CREDENTIAL_ARTIFACT_PREFIX", "credential-artifacts")
_LOCK = threading.RLock()


def _normalise_storage_id(storage_id: Any) -> Optional[str]:
    if not isinstance(storage_id, str):
        return None

    trimmed = storage_id.strip()
    if not trimmed:
        return None

    return trimmed


def _artifact_path(storage_id: str) -> str:
    filename = _artifact_filename(storage_id)
    return os.path.join(_ARTIFACT_DIR, filename)


def _artifact_filename(storage_id: str) -> str:
    digest = hashlib.sha256(storage_id.encode("utf-8")).hexdigest()
    return f"{digest}.json"


def _artifact_blob(storage_id: str) -> str:
    filename = _artifact_filename(storage_id)
    return build_blob_name(filename, prefix=_ARTIFACT_PREFIX)


def _using_gcs() -> bool:
    return gcs_enabled() and bool(os.environ.get("FIDO_SERVER_GCS_BUCKET"))


def _ensure_directory() -> None:
    os.makedirs(_ARTIFACT_DIR, exist_ok=True)


def _read_file(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None


def _write_file(path: str, payload: Dict[str, Any]) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp_path, path)


def _read_record(storage_id: str) -> Optional[Dict[str, Any]]:
    if _using_gcs():
        blob_name = _artifact_blob(storage_id)
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


def _write_record(storage_id: str, record: Dict[str, Any]) -> None:
    if _using_gcs():
        blob_name = _artifact_blob(storage_id)
        payload = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        upload_bytes(blob_name, payload, content_type="application/json")
        return

    _ensure_directory()
    _write_file(_artifact_path(storage_id), record)


def _delete_record(storage_id: str) -> bool:
    if _using_gcs():
        blob_name = _artifact_blob(storage_id)
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


def load_credential_artifact(storage_id: Any) -> Optional[Dict[str, Any]]:
    """Return the stored artifact payload for ``storage_id`` if available."""

    normalised = _normalise_storage_id(storage_id)
    if not normalised:
        return None

    with _LOCK:
        stored = _read_record(normalised)

    if not stored or not isinstance(stored, dict):
        return None

    payload = stored.get("payload")
    if isinstance(payload, dict):
        return payload

    return None


def _merge_payload(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
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
    payload: Dict[str, Any],
    *,
    merge: bool = False,
) -> bool:
    """Persist ``payload`` for ``storage_id``.

    When ``merge`` is true, existing payload keys are shallowly merged with the
    provided payload. Returns ``True`` when the artifact was stored.
    """

    normalised = _normalise_storage_id(storage_id)
    if not normalised or not isinstance(payload, dict):
        return False

    timestamp = time.time()

    with _LOCK:
        existing = _read_record(normalised) if merge else None
        base_payload: Dict[str, Any]
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
            _write_record(normalised, record)
        except Exception:
            return False

    return True


def delete_credential_artifact(storage_id: Any) -> bool:
    """Delete the stored artifact for ``storage_id`` if it exists."""

    normalised = _normalise_storage_id(storage_id)
    if not normalised:
        return False

    with _LOCK:
        return _delete_record(normalised)
