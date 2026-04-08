"""CTAP repair and trailing-merge leaf helpers."""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple

from fido2 import cbor

from .cbor_core import _lenient_decode_from
from .ctap_repair_make import (
    _derive_alg_from_auth_data,
    _extract_mapping_bytes,
    _extract_mapping_string,
    _merge_ctap_make_credential,
    _merge_trailing_signature,
    _repair_make_credential_entries,
)


def _locate_get_assertion_trailing_offset(raw_bytes: bytes, signature_start: int) -> int:
    if not raw_bytes or signature_start >= len(raw_bytes):
        return len(raw_bytes)

    search_start = max(signature_start, len(raw_bytes) - 2048)
    for idx in range(search_start, len(raw_bytes)):
        if raw_bytes[idx] != 0x04:
            continue
        key, after_key = _lenient_decode_from(raw_bytes, idx)
        if key != 4 or after_key <= idx:
            continue
        value, after_value = _lenient_decode_from(raw_bytes, after_key)
        if after_value <= after_key:
            continue
        if isinstance(value, Mapping):
            string_keys = {str(k) for k in value.keys()}
            if string_keys.intersection({"id", "name", "displayName"}):
                return idx
        if isinstance(value, list):
            flattened = []
            for item in value:
                if isinstance(item, Mapping):
                    flattened.extend(str(k) for k in item.keys())
            if any(key in {"id", "name", "displayName"} for key in flattened):
                return idx
    return len(raw_bytes)


def _extract_get_assertion_trailing_from_raw(
    raw_bytes: bytes,
) -> Tuple[Optional[bytes], Dict[int, Any]]:
    if not raw_bytes:
        return None, {}

    signature_offset: Optional[int] = None
    length_size = 0
    for prefix, size in ((0x58, 1), (0x59, 2), (0x5A, 4), (0x5B, 8)):
        marker = bytes((3, prefix))
        idx = raw_bytes.find(marker)
        if idx != -1:
            signature_offset = idx
            length_size = size
            break

    if signature_offset is None or length_size == 0:
        return None, {}

    length_bytes = raw_bytes[signature_offset + 2 : signature_offset + 2 + length_size]
    if len(length_bytes) != length_size:
        return None, {}

    declared_length = int.from_bytes(length_bytes, "big")
    value_offset = signature_offset + 2 + length_size
    declared_end = value_offset + declared_length

    if declared_end > len(raw_bytes):
        trailing_offset = _locate_get_assertion_trailing_offset(raw_bytes, value_offset)
    else:
        trailing_offset = declared_end

    signature_bytes = raw_bytes[value_offset:trailing_offset]
    trailing_fields: Dict[int, Any] = {}

    cursor = trailing_offset
    while cursor < len(raw_bytes):
        key, after_key = _lenient_decode_from(raw_bytes, cursor)
        if after_key <= cursor or not isinstance(key, int):
            break
        value, after_value = _lenient_decode_from(raw_bytes, after_key)
        if after_value <= after_key:
            break
        try:
            encoded_value = cbor.encode(value)
        except Exception:
            encoded_value = None
        if encoded_value is not None:
            expected_end = after_key + len(encoded_value)
            if expected_end <= len(raw_bytes):
                after_value = min(after_value, expected_end)
        trailing_fields[int(key)] = value
        cursor = after_value

    if 5 not in trailing_fields and trailing_offset < len(raw_bytes):
        idx = raw_bytes.rfind(b"\x05", trailing_offset)
        if idx != -1:
            key_candidate, after_key_candidate = _lenient_decode_from(raw_bytes, idx)
            if key_candidate == 5 and after_key_candidate > idx:
                value_candidate, after_value_candidate = _lenient_decode_from(
                    raw_bytes, after_key_candidate
                )
                if after_value_candidate > after_key_candidate:
                    trailing_fields[5] = value_candidate

    return (signature_bytes if signature_bytes else None), trailing_fields


def _split_get_assertion_trailing_fields(
    signature_bytes: bytes,
) -> Tuple[bytes, Dict[int, Any]]:
    if not signature_bytes:
        return signature_bytes, {}

    start_search = max(0, len(signature_bytes) - 1024)
    for offset in range(start_search, len(signature_bytes)):
        if signature_bytes[offset] != 0x04:
            continue

        key, after_key = _lenient_decode_from(signature_bytes, offset)
        if key != 4 or after_key <= offset:
            continue

        value, after_value = _lenient_decode_from(signature_bytes, after_key)
        if after_value <= after_key:
            continue

        trailing_fields: Dict[int, Any] = {4: value}
        cursor = after_value
        success = True

        while cursor < len(signature_bytes):
            next_key, after_next_key = _lenient_decode_from(signature_bytes, cursor)
            if (
                after_next_key <= cursor
                or next_key is None
                or not isinstance(next_key, int)
                or next_key < 4
                or next_key > 8
            ):
                success = False
                break

            next_value, after_next_value = _lenient_decode_from(signature_bytes, after_next_key)
            if after_next_value <= after_next_key:
                success = False
                break

            trailing_fields[int(next_key)] = next_value
            cursor = after_next_value

        if success and cursor == len(signature_bytes):
            return signature_bytes[:offset], trailing_fields

    return signature_bytes, {}


