"""Credential storage helpers using local storage with GCS-compatible paths."""
from __future__ import annotations

import base64
import os
import pickle
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from .cloud_storage import (
    build_blob_name,
    delete_blob,
    download_bytes,
    list_blob_names,
    upload_bytes,
)
from .config import app

__all__ = [
    "add_public_key_material",
    "convert_bytes_for_json",
    "delkey",
    "extract_credential_data",
    "iter_credentials",
    "list_credentials",
    "readkey",
    "savekey",
]

# These prefixes match the GCS bucket structure
# Users can copy their GCS bucket contents directly to the storage folder
_USER_FOLDER_PREFIX = os.environ.get(
    "FIDO_SERVER_USER_FOLDER_PREFIX",
    os.environ.get("FIDO_SERVER_GCS_USER_FOLDER_PREFIX",
    os.environ.get("FIDO_SERVER_GCS_CREDENTIAL_PREFIX", "user-data")),
)
_USER_CREDENTIAL_SUBDIR = os.environ.get(
    "FIDO_SERVER_USER_CREDENTIAL_SUBDIR",
    os.environ.get("FIDO_SERVER_GCS_USER_CREDENTIAL_SUBDIR",
    os.environ.get("FIDO_SERVER_GCS_CREDENTIAL_PREFIX", "credentials")),
)


def _user_root_prefix(session_id: str) -> str:
    """Build the root prefix for a user's data."""
    if not isinstance(session_id, str):
        raise ValueError("Session identifier must be a string")
    cleaned = session_id.strip()
    if not cleaned:
        raise ValueError("Session identifier is empty")
    return build_blob_name(cleaned, prefix=_USER_FOLDER_PREFIX)


def _credential_prefix(session_id: str) -> str:
    """Build the prefix for a user's credential files."""
    root = _user_root_prefix(session_id)
    return build_blob_name(_USER_CREDENTIAL_SUBDIR, prefix=root)


def _credential_blob(name: str, session_id: str) -> str:
    """Build the blob name for a credential file."""
    if not isinstance(name, str):
        raise ValueError("Credential identifier must be a string")
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("Credential identifier is empty")
    filename = f"{cleaned}_credential_data.pkl"
    prefix = _credential_prefix(session_id)
    return build_blob_name(filename, prefix=prefix)


def _legacy_credential_blob(name: str) -> str:
    """Build the legacy blob name for backward compatibility."""
    if not isinstance(name, str):
        raise ValueError("Credential identifier must be a string")
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("Credential identifier is empty")
    filename = f"{cleaned}_credential_data.pkl"
    return build_blob_name(filename, prefix=_USER_FOLDER_PREFIX)


def _build_search_prefix(path: str) -> str:
    """Build a search prefix from a path."""
    base_prefix = path.strip().strip("/")
    return f"{base_prefix}/" if base_prefix else ""


def _candidate_blob_names(name: str, session_id: str) -> Iterable[str]:
    """Generate candidate blob names for a credential (current and legacy)."""
    seen = set()
    for blob_name in (
        _credential_blob(name, session_id),
        _legacy_credential_blob(name),
    ):
        if blob_name in seen:
            continue
        seen.add(blob_name)
        yield blob_name


def _list_credential_blob_names(session_id: str) -> Iterable[Tuple[str, str]]:
    """List all credential blob names for a session."""
    search_prefixes = []

    primary_prefix = _build_search_prefix(_credential_prefix(session_id))
    search_prefixes.append(primary_prefix)

    legacy_prefix = _build_search_prefix(_USER_FOLDER_PREFIX)
    if legacy_prefix not in search_prefixes:
        search_prefixes.append(legacy_prefix)

    seen_users = set()
    for search_prefix in search_prefixes:
        try:
            for blob_name in list_blob_names(search_prefix):
                remainder = blob_name[len(search_prefix):] if search_prefix else blob_name
                if search_prefix == legacy_prefix and "/" in remainder.strip("/"):
                    continue
                if not remainder.endswith("_credential_data.pkl"):
                    continue
                username = remainder[: -len("_credential_data.pkl")]
                if not username or username in seen_users:
                    continue
                seen_users.add(username)
                yield username, blob_name
        except Exception as exc:
            app.logger.warning(
                "Unable to list credential blobs under %s: %s", search_prefix, exc
            )


def _resolve_session_id(session_id: Optional[str] = None) -> str:
    """Resolve the session ID, using the metadata session if not provided."""
    if isinstance(session_id, str):
        trimmed = session_id.strip()
        if trimmed:
            return trimmed

    from .metadata import ensure_metadata_session_id

    return ensure_metadata_session_id()


def savekey(name: str, key: Any, *, session_id: Optional[str] = None) -> None:
    """Save a credential to storage."""
    payload = pickle.dumps(key)
    resolved_session = _resolve_session_id(session_id)
    blob_name = _credential_blob(name, resolved_session)
    upload_bytes(blob_name, payload, content_type="application/octet-stream")


def readkey(name: str, *, session_id: Optional[str] = None) -> List[Any]:
    """Read a credential from storage."""
    resolved_session = _resolve_session_id(session_id)
    payload = None
    for blob_name in _candidate_blob_names(name, resolved_session):
        try:
            payload = download_bytes(blob_name)
        except Exception:
            payload = None
        if payload:
            break
    if not payload:
        return []

    try:
        creds = pickle.loads(payload)
    except Exception:
        return []
    return creds if isinstance(creds, list) else []


def delkey(name: str, *, session_id: Optional[str] = None) -> None:
    """Delete a credential from storage."""
    resolved_session = _resolve_session_id(session_id)
    for blob_name in _candidate_blob_names(name, resolved_session):
        try:
            delete_blob(blob_name, missing_ok=True)
        except Exception:
            pass


def iter_credentials(*, session_id: Optional[str] = None) -> Iterator[Tuple[str, List[Any]]]:
    """Iterate over all credentials for a session."""
    resolved_session = _resolve_session_id(session_id)

    for username, blob_name in _list_credential_blob_names(resolved_session):
        try:
            payload = download_bytes(blob_name)
        except Exception:
            continue
        if not payload:
            continue

        try:
            creds = pickle.loads(payload)
        except Exception:
            continue
        if isinstance(creds, list):
            yield username, creds


def list_credentials(*, session_id: Optional[str] = None) -> Dict[str, List[Any]]:
    """List all credentials for a session."""
    entries: Dict[str, List[Any]] = {}
    for username, creds in iter_credentials(session_id=session_id):
        entries[username] = creds
    return entries


def convert_bytes_for_json(obj: Any) -> Any:
    """Recursively convert bytes-like objects to base64 strings for JSON serialization."""
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(obj)).decode('utf-8')
    if isinstance(obj, dict):
        return {k: convert_bytes_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert_bytes_for_json(item) for item in obj]
    return obj


def add_public_key_material(target: Dict[str, Any], public_key: Any) -> None:
    """Populate JSON-friendly COSE public key details if available."""
    if not isinstance(public_key, dict):
        return

    cose_map = dict(public_key)
    target['publicKeyCose'] = convert_bytes_for_json(cose_map)

    raw_key = cose_map.get(-1)
    if isinstance(raw_key, (bytes, bytearray, memoryview)):
        target['publicKeyBytes'] = convert_bytes_for_json(raw_key)

    if 'publicKeyType' not in target:
        target['publicKeyType'] = cose_map.get(1)

    if 'publicKeyAlgorithm' not in target:
        target['publicKeyAlgorithm'] = cose_map.get(3)


def extract_credential_data(cred: Any) -> Any:
    """Extract AttestedCredentialData from either old or new storage format."""
    if isinstance(cred, dict):
        return cred['credential_data']
    return cred
