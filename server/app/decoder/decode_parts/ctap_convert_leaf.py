"""CTAP user/descriptor conversion leaf helpers."""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

import cbor2
from fido2.utils import ByteBuffer

from .key_utils import MISSING, coerce_cbor_bytes as _coerce_cbor_bytes, get_mapping_entry as _get_mapping_entry, hex_json_safe as _hex_json_safe


def _convert_optional_ctap_field(value: Any) -> Any:
    data_bytes = _coerce_cbor_bytes(value)
    if data_bytes is not None:
        return data_bytes.hex()
    return _hex_json_safe(value)


def _convert_ctap_credential_descriptor(entry: Any) -> Any:
    data_bytes = _coerce_cbor_bytes(entry)
    if data_bytes is not None:
        return data_bytes.hex()
    if not isinstance(entry, Mapping):
        return _hex_json_safe(entry)

    descriptor: Dict[str, Any] = {}
    id_value = _get_mapping_entry(entry, "id", 1)
    if id_value is not MISSING:
        id_bytes = _coerce_cbor_bytes(id_value)
        if id_bytes is not None:
            descriptor["id"] = id_bytes.hex()

    type_value = _get_mapping_entry(entry, "type", 2)
    if type_value is not MISSING:
        descriptor["type"] = _hex_json_safe(type_value)

    transports_value = _get_mapping_entry(entry, "transports", 3)
    if transports_value is not MISSING:
        descriptor["transports"] = _hex_json_safe(transports_value)

    for key in entry:
        if key in {"id", "type", "transports"} or key in {1, 2, 3}:
            continue
        descriptor[str(key)] = _hex_json_safe(entry[key])

    return descriptor


def _attempt_decode_cbor_map(data: bytes) -> Optional[Mapping[Any, Any]]:
    try:
        decoded = cbor2.loads(data)
    except Exception:  # pragma: no cover - defensive
        return None
    return decoded if isinstance(decoded, Mapping) else None


def _normalize_user_mapping(entry: Mapping[Any, Any]) -> Mapping[Any, Any]:
    normalized: Dict[Any, Any] = {}
    for key, value in entry.items():
        if isinstance(key, ByteBuffer):
            candidate_key = key.getvalue()
        else:
            candidate_key = key

        if isinstance(candidate_key, (bytes, bytearray, memoryview)):
            raw_key = bytes(candidate_key)
            try:
                normalized_key: Any = raw_key.decode("utf-8")
            except UnicodeDecodeError:
                normalized_key = raw_key.hex()
        else:
            normalized_key = candidate_key

        normalized[normalized_key] = value
    return normalized
