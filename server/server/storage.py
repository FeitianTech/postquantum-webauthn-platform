"""Credential storage helpers for the demo server backed by pluggable storage."""
from __future__ import annotations

import base64
import os
import pickle
from typing import Any, Dict, Iterable, Iterator, List, Tuple

from .cloud_storage import (
    build_blob_name,
    delete_blob,
    download_bytes,
    gcs_enabled,
    list_blob_names,
    upload_bytes,
)
from .config import basepath

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


_CREDENTIAL_PREFIX = os.environ.get("FIDO_SERVER_GCS_CREDENTIAL_PREFIX", "credentials")


def _using_gcs() -> bool:
    return gcs_enabled() and bool(os.environ.get("FIDO_SERVER_GCS_BUCKET"))


def _credential_blob(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("Credential identifier must be a string")
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("Credential identifier is empty")
    filename = f"{cleaned}_credential_data.pkl"
    return build_blob_name(filename, prefix=_CREDENTIAL_PREFIX)


def _list_credential_blob_names() -> Iterable[Tuple[str, str]]:
    base_prefix = (_CREDENTIAL_PREFIX or "").strip().strip("/")
    search_prefix = f"{base_prefix}/" if base_prefix else ""
    for blob_name in list_blob_names(search_prefix):
        remainder = blob_name[len(search_prefix) :] if search_prefix else blob_name
        if not remainder.endswith("_credential_data.pkl"):
            continue
        username = remainder[: -len("_credential_data.pkl")]
        if not username:
            continue
        yield username, blob_name


def _local_filename(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("Credential identifier must be a string")
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("Credential identifier is empty")
    return os.path.join(basepath, f"{cleaned}_credential_data.pkl")


def savekey(name: str, key: Any) -> None:
    payload = pickle.dumps(key)
    if _using_gcs():
        blob_name = _credential_blob(name)
        upload_bytes(blob_name, payload, content_type="application/octet-stream")
    else:
        with open(_local_filename(name), "wb") as f:
            f.write(payload)


def readkey(name: str) -> List[Any]:
    if _using_gcs():
        blob_name = _credential_blob(name)
        try:
            payload = download_bytes(blob_name)
        except Exception:
            return []
        if not payload:
            return []
    else:
        try:
            with open(_local_filename(name), "rb") as f:
                payload = f.read()
        except Exception:
            return []

    try:
        creds = pickle.loads(payload)
    except Exception:
        return []
    return creds if isinstance(creds, list) else []


def delkey(name: str) -> None:
    if _using_gcs():
        blob_name = _credential_blob(name)
        try:
            delete_blob(blob_name, missing_ok=True)
        except Exception:
            pass
    else:
        try:
            os.remove(_local_filename(name))
        except Exception:
            pass


def iter_credentials() -> Iterator[Tuple[str, List[Any]]]:
    if _using_gcs():
        sources: Iterable[Tuple[str, bytes]] = []

        def _download_blob_items() -> Iterable[Tuple[str, bytes]]:
            for username, blob_name in _list_credential_blob_names():
                try:
                    payload = download_bytes(blob_name)
                except Exception:
                    continue
                if payload:
                    yield username, payload

        sources = _download_blob_items()
    else:
        def _read_local_items() -> Iterable[Tuple[str, bytes]]:
            for entry in os.listdir(basepath):
                if not entry.endswith("_credential_data.pkl"):
                    continue
                username = entry[: -len("_credential_data.pkl")]
                if not username:
                    continue
                path = os.path.join(basepath, entry)
                try:
                    with open(path, "rb") as f:
                        payload = f.read()
                except Exception:
                    continue
                if payload:
                    yield username, payload

        sources = _read_local_items()

    for username, payload in sources:
        try:
            creds = pickle.loads(payload)
        except Exception:
            continue
        if isinstance(creds, list):
            yield username, creds


def list_credentials() -> Dict[str, List[Any]]:
    entries: Dict[str, List[Any]] = {}
    for username, creds in iter_credentials():
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
