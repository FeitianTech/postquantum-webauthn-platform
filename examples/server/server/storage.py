"""Credential storage helpers for the demo server."""
from __future__ import annotations

import base64
import os
import pickle
from collections.abc import Mapping
from typing import Any, Dict, List, Optional

from .config import basepath

__all__ = [
    "add_public_key_material",
    "coerce_cose_public_key_dict",
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


def coerce_cose_public_key_dict(public_key: Any) -> Optional[Dict[Any, Any]]:
    """Return ``public_key`` as a plain ``dict`` when it resembles a COSE map."""

    if isinstance(public_key, Mapping):
        return dict(public_key)

    if hasattr(public_key, "items"):
        try:
            return dict(public_key.items())  # type: ignore[call-arg]
        except Exception:
            pass

    try:
        return dict(public_key)
    except Exception:
        return None


def add_public_key_material(
    target: Dict[str, Any],
    public_key: Any,
    *,
    field_prefix: str = "",
) -> None:
    """Populate JSON-friendly COSE public key details if available.

    When ``field_prefix`` is provided, generated keys (``publicKeyCose``,
    ``publicKeyBytes`` and associated metadata) are prefixed with that value,
    e.g. ``field_prefix="credential"`` produces ``credentialPublicKeyCose``.
    """

    cose_map = coerce_cose_public_key_dict(public_key)
    if not cose_map:
        return

    prefix = field_prefix or ""

    def _field(name: str) -> str:
        if not prefix:
            return name
        return f"{prefix}{name[0].upper()}{name[1:]}"

    target[_field('publicKeyCose')] = convert_bytes_for_json(cose_map)

    raw_key = cose_map.get(-1)
    if isinstance(raw_key, (bytes, bytearray, memoryview)):
        target[_field('publicKeyBytes')] = convert_bytes_for_json(raw_key)

    type_field = _field('publicKeyType')
    if type_field not in target:
        target[type_field] = cose_map.get(1)

    alg_field = _field('publicKeyAlgorithm')
    if alg_field not in target:
        target[alg_field] = cose_map.get(3)


def extract_credential_data(cred: Any) -> Any:
    """Extract AttestedCredentialData from either old or new storage format."""
    if isinstance(cred, dict):
        return cred['credential_data']
    return cred
