"""CTAP numeric-key parsing and classification helpers."""
from __future__ import annotations

from collections import deque
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .binary_decode import _maybe_decode_bytes
from .constants import _CTAP_LABELED_KEY_PATTERN


def _extract_ctap_numeric_payload(parsed: Any) -> Tuple[Dict[int, Any], str]:
    """Locate and sanitize a CTAP/WebAuthn numeric-keyed mapping within ``parsed``."""

    def _enqueue_candidates(queue: deque[Any], value: Any, visited: set[int]) -> None:
        if isinstance(value, Mapping):
            marker = id(value)
            if marker in visited:
                return
            visited.add(marker)
            queue.append(value)
            return

        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for entry in value:
                _enqueue_candidates(queue, entry, visited)

    visited: set[int] = set()
    candidates: deque[Any] = deque()
    _enqueue_candidates(candidates, parsed, visited)

    classification_error: Optional[ValueError] = None

    while candidates:
        candidate = candidates.popleft()

        try:
            numeric_map = _sanitize_ctap_numeric_mapping(candidate)
        except ValueError:
            salvage_map: Dict[int, Any] = {}
            salvage_error: Optional[ValueError] = None
            if isinstance(candidate, Mapping):
                for key, value in candidate.items():
                    try:
                        index = _coerce_ctap_numeric_key(key)
                    except ValueError as exc:
                        salvage_map = {}
                        salvage_error = exc
                        break
                    if index is None:
                        continue
                    if index in salvage_map:
                        salvage_map = {}
                        salvage_error = ValueError(
                            f"Duplicate field 0x{index:02x} detected in CTAP/WebAuthn input."
                        )
                        break
                    salvage_map[index] = value

            if salvage_map:
                try:
                    ctap_type = _classify_ctap_numeric_mapping(salvage_map)
                except ValueError as exc:
                    if classification_error is None:
                        classification_error = exc
                else:
                    return salvage_map, ctap_type

            if salvage_error is not None and classification_error is None:
                classification_error = salvage_error
        else:
            try:
                ctap_type = _classify_ctap_numeric_mapping(numeric_map)
            except ValueError as exc:
                if classification_error is None:
                    classification_error = exc
            else:
                return numeric_map, ctap_type

        if isinstance(candidate, Mapping):
            for value in candidate.values():
                _enqueue_candidates(candidates, value, visited)

    if classification_error is not None:
        raise classification_error

    raise ValueError(
        "Unable to locate CTAP/WebAuthn numeric-keyed fields in input JSON."
    )


def _sanitize_ctap_numeric_mapping(parsed: Mapping[Any, Any]) -> Dict[int, Any]:
    numeric_map: Dict[int, Any] = {}
    for key, value in parsed.items():
        index = _coerce_ctap_numeric_key(key)
        if index is None:
            raise ValueError(
                "CTAP/WebAuthn encoding requires numeric keys such as \"01\" or \"02\"."
            )
        if index in numeric_map:
            raise ValueError(f"Duplicate field 0x{index:02x} detected in CTAP/WebAuthn input.")
        numeric_map[index] = value

    if not numeric_map:
        raise ValueError("CTAP/WebAuthn encoding expects at least one CTAP field.")

    return numeric_map


def _coerce_ctap_numeric_key(key: Any) -> Optional[int]:
    if isinstance(key, int):
        index = key
    elif isinstance(key, str):
        stripped = key.strip()
        if not stripped:
            return None
        match = _CTAP_LABELED_KEY_PATTERN.match(stripped)
        if match:
            stripped = match.group(1).strip()
        if stripped.lower().startswith("0x"):
            try:
                index = int(stripped, 16)
            except ValueError:
                return None
        elif stripped.isdigit():
            index = int(stripped, 10)
        else:
            return None
    else:
        return None

    if index < 0:
        raise ValueError(
            f"CTAP/WebAuthn field numbers must be non-negative (received {index})."
        )
    return index


def _classify_ctap_numeric_mapping(mapping: Mapping[int, Any]) -> str:
    if not mapping:
        raise ValueError("CTAP/WebAuthn encoding expects at least one CTAP field.")

    field_two = mapping.get(2)
    if field_two is None:
        raise ValueError("Missing field 0x02 (authData/clientDataHash/rp)")

    signature_candidate = mapping.get(3)
    signature_bytes = (
        _maybe_decode_bytes(signature_candidate) if signature_candidate is not None else None
    )
    if signature_bytes is not None:
        field_two_bytes = _maybe_decode_bytes(field_two)
        if field_two_bytes is None:
            raise ValueError(
                "Field 0x02 (authData) must be binary data for GetAssertion response."
            )
        if len(field_two_bytes) < 37:
            raise ValueError(
                "Field 0x02 (authData) must contain authenticator data for GetAssertion response."
            )
        return "getAssertionResponse"

    field_one = mapping.get(1)
    if field_one is None:
        raise ValueError("Missing field 0x01 (clientDataHash/rpId/fmt/credential)")

    field_one_bytes = _maybe_decode_bytes(field_one)
    if field_one_bytes is not None:
        if len(field_one_bytes) != 32:
            raise ValueError(
                "Field 0x01 (clientDataHash) must be exactly 32 bytes for MakeCredential request."
            )
        if not isinstance(field_two, Mapping):
            raise ValueError("Field 0x02 (rp) must be an object for MakeCredential request.")
        return "makeCredentialRequest"

    if isinstance(field_one, str) and field_one.strip():
        field_two_bytes = _maybe_decode_bytes(field_two)
        if field_two_bytes is None:
            raise ValueError(
                "Field 0x02 (authData/clientDataHash) must be binary data."
            )
        if len(field_two_bytes) == 32:
            return "getAssertionRequest"
        if len(field_two_bytes) >= 37:
            return "makeCredentialResponse"
        raise ValueError(
            "Field 0x02 (authData/clientDataHash) length is not valid for CTAP/WebAuthn data."
        )

    raise ValueError(
        "Unable to classify CTAP/WebAuthn data. Provide MakeCredential/GetAssertion request or response fields."
    )


def _normalize_ctap_extra_value(value: Any) -> Any:
    decoded = _maybe_decode_bytes(value)
    if decoded is not None:
        return decoded

    if isinstance(value, Mapping):
        cleaned: Dict[str, Any] = {}
        for key, entry in value.items():
            cleaned[_sanitize_nested_extra_key(key)] = _normalize_ctap_extra_value(entry)
        return cleaned

    if isinstance(value, list):
        return [_normalize_ctap_extra_value(entry) for entry in value]

    return value


def _sanitize_nested_extra_key(key: Any) -> str:
    if isinstance(key, str):
        stripped = key.strip()
        if not stripped:
            return ""
        match = _CTAP_LABELED_KEY_PATTERN.match(stripped)
        if match:
            label = match.group(2).strip()
            if label:
                return label
            stripped = match.group(1).strip()
        return stripped
    return str(key)
