"""Server-side storage for advanced credential artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, Optional

from .config import basepath

__all__ = [
    "store_credential_artifact",
    "load_credential_artifact",
    "delete_credential_artifact",
]


_ARTIFACT_DIR = os.path.join(basepath, "static", "credential-artifacts")
_LOCK = threading.RLock()


def _normalise_storage_id(storage_id: Any) -> Optional[str]:
    if not isinstance(storage_id, str):
        return None

    trimmed = storage_id.strip()
    if not trimmed:
        return None

    return trimmed


def _artifact_path(storage_id: str) -> str:
    digest = hashlib.sha256(storage_id.encode("utf-8")).hexdigest()
    filename = f"{digest}.json"
    return os.path.join(_ARTIFACT_DIR, filename)


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


def load_credential_artifact(storage_id: Any) -> Optional[Dict[str, Any]]:
    """Return the stored artifact payload for ``storage_id`` if available."""

    normalised = _normalise_storage_id(storage_id)
    if not normalised:
        return None

    path = _artifact_path(normalised)

    with _LOCK:
        stored = _read_file(path)

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
    path = _artifact_path(normalised)

    with _LOCK:
        _ensure_directory()
        existing = _read_file(path) if merge else None
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

        _write_file(path, record)

    return True


def delete_credential_artifact(storage_id: Any) -> bool:
    """Delete the stored artifact for ``storage_id`` if it exists."""

    normalised = _normalise_storage_id(storage_id)
    if not normalised:
        return False

    path = _artifact_path(normalised)

    with _LOCK:
        try:
            os.remove(path)
        except FileNotFoundError:
            return False
        except OSError:
            return False

    return True
