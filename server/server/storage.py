"""Credential storage helpers for the demo server."""
from __future__ import annotations

import base64
import os
import pickle
from typing import Any, Dict, List

from .config import basepath

__all__ = [
    "add_public_key_material",
    "convert_bytes_for_json",
    "delkey",
    "extract_credential_data",
    "readkey",
    "savekey",
]


def savekey(name: str, key: Any) -> None:
    filename = f"{name}_credential_data.pkl"
    with open(os.path.join(basepath, filename), "wb") as f:
        f.write(pickle.dumps(key))


def readkey(name: str) -> List[Any]:
    filename = f"{name}_credential_data.pkl"
    try:
        with open(os.path.join(basepath, filename), "rb") as f:
            creds = pickle.loads(f.read())
            return creds
    except Exception:
        return []


def delkey(name: str) -> None:
    filename = f"{name}_credential_data.pkl"
    try:
        os.remove(os.path.join(basepath, filename))
    except Exception:
        pass


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
