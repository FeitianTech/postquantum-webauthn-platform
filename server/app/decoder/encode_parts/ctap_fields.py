"""CTAP field lookup/coercion helpers and nested structure encoders."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .binary_decode import (
    _maybe_decode_bytes,
    _require_bytes,
    _require_certificate_bytes,
)
from .binary_extract import _restore_generic_structure
from .constants import _CTAP_LABELED_KEY_PATTERN


def _get_ctap_field_value(
    structure: Mapping[str, Any],
    label: str,
    index: Optional[int] = None,
) -> Any:
    candidates = {label.lower()}
    if index is not None:
        candidates.add(str(index))
        candidates.add(f"{index} ({label})")

    for key, value in structure.items():
        if _ctap_key_matches(key, candidates):
            return value
    return None


def _ctap_key_matches(key: Any, candidates: Iterable[str]) -> bool:
    key_str = str(key).strip()
    key_lower = key_str.lower()
    normalized_candidates = {candidate.strip() for candidate in candidates}
    normalized_lower = {candidate.lower() for candidate in normalized_candidates}

    if key_str in normalized_candidates or key_lower in normalized_lower:
        return True

    if isinstance(key, str):
        match = _CTAP_LABELED_KEY_PATTERN.match(key)
        if match:
            number = match.group(1).strip()
            label = match.group(2).strip()
            if number in normalized_candidates or number.lower() in normalized_lower:
                return True
            if label in normalized_candidates or label.lower() in normalized_lower:
                return True
    return False


def _require_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    raise ValueError(f"{field_name} must be an object for encoding.")


def _ensure_text(value: Any, field_name: str) -> str:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    raise ValueError(f"{field_name} must be a non-empty string.")


def _ensure_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer, not a boolean.")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return int(value.strip(), 0)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an integer value.") from exc
    raise ValueError(f"{field_name} must be an integer value.")


def _ensure_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    raise ValueError(f"{field_name} must be a boolean value.")


def _encode_attestation_statement(value: Any) -> Any:
    if value is None:
        return None

    if not isinstance(value, Mapping):
        return _require_bytes(value, "attStmt")

    statement: Dict[str, Any] = {}
    for key, entry in value.items():
        if key == "sig":
            statement["sig"] = _require_bytes(entry, "attStmt.sig")
        elif key == "x5c":
            if not isinstance(entry, Sequence):
                raise ValueError("attStmt.x5c must be an array of certificates.")
            statement["x5c"] = [
                _require_certificate_bytes(item, index)
                for index, item in enumerate(entry)
            ]
        else:
            decoded = _maybe_decode_bytes(entry)
            statement[key] = (
                decoded if decoded is not None else _restore_generic_structure(entry)
            )
    return statement


def _encode_ctap_user(value: Any) -> Dict[str, Any]:
    mapping = _require_mapping(value, "user")
    result: Dict[str, Any] = {}

    if "id" in mapping:
        result["id"] = _require_bytes(mapping["id"], "user.id")
    if "name" in mapping:
        result["name"] = _ensure_text(mapping["name"], "user.name")
    if "displayName" in mapping:
        result["displayName"] = _ensure_text(mapping["displayName"], "user.displayName")
    if "icon" in mapping and mapping["icon"] is not None:
        result["icon"] = _ensure_text(str(mapping["icon"]), "user.icon")

    for key, entry in mapping.items():
        if key in {"id", "name", "displayName", "icon"}:
            continue
        decoded = _maybe_decode_bytes(entry)
        result[str(key)] = decoded if decoded is not None else _restore_generic_structure(entry)

    return result


def _encode_allow_list(value: Any) -> List[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_encode_credential_descriptor(item) for item in value]
    raise ValueError("allowList must be an array of credential descriptors.")


def _encode_credential_descriptor(value: Any) -> Any:
    decoded = _maybe_decode_bytes(value)
    if decoded is not None:
        return decoded

    mapping = _require_mapping(value, "credential descriptor")
    descriptor: Dict[str, Any] = {}

    if "type" in mapping:
        descriptor["type"] = _ensure_text(mapping["type"], "credential.type")
    if "id" in mapping:
        descriptor["id"] = _require_bytes(mapping["id"], "credential.id")
    if "transports" in mapping:
        descriptor["transports"] = _restore_generic_structure(mapping["transports"])

    for key, entry in mapping.items():
        if key in {"type", "id", "transports"}:
            continue
        decoded_entry = _maybe_decode_bytes(entry)
        descriptor[str(key)] = (
            decoded_entry
            if decoded_entry is not None
            else _restore_generic_structure(entry)
        )

    return descriptor
