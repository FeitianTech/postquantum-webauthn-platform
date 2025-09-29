"""Credential storage helpers for the demo server."""
from __future__ import annotations

import base64
import binascii
import os
import pickle
from collections import deque
from collections.abc import Mapping, MutableMapping
from typing import Any, Dict, Iterable, List, Mapping as MappingType, Optional

from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from .attestation import colon_hex, format_hex_bytes_lines

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
        raw_bytes = bytes(raw_key)
        target[_field('publicKeyBytes')] = convert_bytes_for_json(raw_bytes)
        target[_field('publicKeyHex')] = colon_hex(raw_bytes)
        hex_lines = format_hex_bytes_lines(raw_bytes)
        if hex_lines:
            target[_field('publicKeyHexLines')] = hex_lines

    type_field = _field('publicKeyType')
    if type_field not in target:
        target[type_field] = cose_map.get(1)

    alg_field = _field('publicKeyAlgorithm')
    if alg_field not in target:
        target[alg_field] = cose_map.get(3)


def _refresh_authenticator_container(
    container: MutableMapping[str, Any],
    credential_data: AttestedCredentialData,
) -> None:
    """Ensure any stored authenticator data mirrors *credential_data*."""

    auth_data_value = container.get("auth_data")

    if isinstance(auth_data_value, AuthenticatorData):
        try:
            refreshed = AuthenticatorData.create(
                bytes(auth_data_value.rp_id_hash),
                auth_data_value.flags,
                auth_data_value.counter,
                bytes(credential_data),
                getattr(auth_data_value, "extensions", None),
            )
        except Exception:
            return
        container["auth_data"] = refreshed
        return

    if isinstance(auth_data_value, MutableMapping):
        nested = auth_data_value.get("credential_data")
        if isinstance(nested, MutableMapping):
            nested = dict(nested)
            nested["public_key"] = dict(credential_data.public_key)
            auth_data_value["credential_data"] = nested
        nested_alt = auth_data_value.get("credentialData")
        if isinstance(nested_alt, MutableMapping):
            nested_alt = dict(nested_alt)
            nested_alt["public_key"] = dict(credential_data.public_key)
            auth_data_value["credentialData"] = nested_alt


def extract_credential_data(cred: Any) -> Any:
    """Extract AttestedCredentialData from either old or new storage format."""

    def _coerce_attested_with_key(
        credential_data: Any, metadata: MappingType[str, Any]
    ) -> Any:
        """Ensure ``credential_data`` exposes the credential public key."""

        preferred_key = _recover_stored_credential_cose_key(metadata)
        if preferred_key is None:
            return credential_data

        if isinstance(credential_data, AttestedCredentialData):
            try:
                current_key = CoseKey.parse(dict(credential_data.public_key))
            except Exception:
                current_key = None

            if current_key is None or dict(current_key) != dict(preferred_key):
                try:
                    updated = AttestedCredentialData.create(
                        bytes(credential_data.aaguid),
                        bytes(credential_data.credential_id),
                        preferred_key,
                    )
                except Exception:
                    return credential_data
                return updated
            return credential_data

        if isinstance(credential_data, Mapping):
            new_data: Dict[Any, Any] = dict(credential_data)
            new_data["public_key"] = dict(preferred_key)
            return new_data

        return credential_data

    if isinstance(cred, dict):
        credential_data = cred.get("credential_data")
        if credential_data is not None:
            updated = _coerce_attested_with_key(credential_data, cred)
            if isinstance(updated, AttestedCredentialData):
                if updated is not credential_data:
                    cred["credential_data"] = updated
                if isinstance(cred, MutableMapping):
                    _refresh_authenticator_container(cred, updated)
            elif isinstance(updated, Mapping) and isinstance(cred, MutableMapping):
                new_mapping = updated if isinstance(updated, dict) else dict(updated)
                cred["credential_data"] = new_mapping
                auth_container = cred.get("auth_data")
                if isinstance(auth_container, MutableMapping):
                    nested = auth_container.get("credential_data")
                    if isinstance(nested, MutableMapping):
                        nested = dict(nested)
                        nested["public_key"] = dict(new_mapping.get("public_key", {}))
                        auth_container["credential_data"] = nested
                    alt_nested = auth_container.get("credentialData")
                    if isinstance(alt_nested, MutableMapping):
                        alt_nested = dict(alt_nested)
                        alt_nested["public_key"] = dict(new_mapping.get("public_key", {}))
                        auth_container["credentialData"] = alt_nested
            return updated

        if "public_key" in cred:
            updated_mapping = _coerce_attested_with_key(cred, cred)
            if isinstance(updated_mapping, Mapping):
                if isinstance(cred, MutableMapping):
                    nested = cred.get("auth_data")
                    if isinstance(nested, MutableMapping):
                        nested = dict(nested)
                        nested["credential_data"] = dict(updated_mapping)
                        cred["auth_data"] = nested
            return updated_mapping

    return cred


_COSE_BYTE_LABELS = {-1, -2, -3, -4, -5, -6}


def _decode_base64_string(value: str) -> Optional[bytes]:
    stripped = value.strip()
    if not stripped:
        return b""

    padding = "=" * ((4 - len(stripped) % 4) % 4)
    padded = stripped + padding

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(padded)
        except (binascii.Error, ValueError):
            continue

    try:
        return bytes.fromhex(stripped)
    except ValueError:
        return None


def _coerce_cose_label(label: Any) -> Any:
    if isinstance(label, int):
        return label
    if isinstance(label, str):
        stripped = label.strip()
        if stripped and stripped.lstrip("-").isdigit():
            try:
                return int(stripped, 10)
            except ValueError:
                return label
    return label


def _decode_cose_value(label: Any, value: Any) -> Any:
    if isinstance(value, str) and isinstance(label, int) and label in _COSE_BYTE_LABELS:
        decoded = _decode_base64_string(value)
        if decoded is not None:
            return decoded
    if isinstance(value, list):
        return [_decode_cose_value(label, item) for item in value]
    if isinstance(value, Mapping):
        return {
            _coerce_cose_label(key): _decode_cose_value(_coerce_cose_label(key), item)
            for key, item in value.items()
        }
    return value


def _normalise_cose_map(
    data: Mapping[Any, Any],
    *,
    raw_bytes: Optional[bytes] = None,
) -> Dict[Any, Any]:
    normalised: Dict[Any, Any] = {}
    for key, value in data.items():
        label = _coerce_cose_label(key)
        normalised[label] = _decode_cose_value(label, value)

    if raw_bytes is not None:
        normalised[-1] = raw_bytes

    return normalised


def _iter_metadata_containers(source: MappingType[str, Any]) -> Iterable[Mapping[str, Any]]:
    queue: deque[Mapping[str, Any]] = deque()
    queue.append(source)
    seen: set[int] = set()

    while queue:
        current = queue.popleft()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        yield current

        for key in ("properties", "relying_party", "relyingParty"):
            nested = current.get(key)
            if isinstance(nested, Mapping):
                queue.append(nested)
                if key in {"relying_party", "relyingParty"}:
                    registration = nested.get("registrationData")
                    if isinstance(registration, Mapping):
                        queue.append(registration)


def _recover_stored_credential_cose_key(
    source: MappingType[str, Any]
) -> Optional[CoseKey]:
    for container in _iter_metadata_containers(source):
        raw_bytes: Optional[bytes] = None
        for byte_field in ("credentialPublicKeyBytes", "publicKeyBytes"):
            byte_value = container.get(byte_field)
            if isinstance(byte_value, str):
                decoded = _decode_base64_string(byte_value)
                if decoded is not None:
                    raw_bytes = decoded
                    break

        for field in (
            "credentialPublicKeyCose",
            "credentialPublicKey",
            "publicKeyCose",
        ):
            candidate = container.get(field)
            if not isinstance(candidate, Mapping):
                continue

            normalised = _normalise_cose_map(candidate, raw_bytes=raw_bytes)
            try:
                return CoseKey.parse(normalised)
            except Exception:
                continue

    return None
