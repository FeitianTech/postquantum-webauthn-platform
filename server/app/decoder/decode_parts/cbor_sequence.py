"""CBOR sequence decoding orchestration extracted from decode facade."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple


def _decode_cbor_sequence_impl(
    payload: bytes,
    *,
    cbor_decode_from: Callable[[bytes], Tuple[Any, bytes]],
    cbor_decoder_factory: Callable[[bytes], Tuple[Any, int]],
    decode_cbor_structure: Callable[[bytes], Tuple[Dict[str, Any], int]],
    structure_to_value: Callable[[Dict[str, Any]], Any],
    lenient_decode_from: Callable[[bytes, int], Tuple[Any, int]],
    json_safe_with_stringified_keys: Callable[[Any], Any],
    cbor_error_type: type,
) -> Tuple[List[Dict[str, Any]], List[Any], int, bytes]:
    structures: List[Dict[str, Any]] = []
    values: List[Any] = []
    consumed_total = 0
    remaining = payload

    while remaining:
        predecoded_structure: Optional[Dict[str, Any]] = None
        try:
            value, rest_after_value = cbor_decode_from(remaining)
            consumed_value = len(remaining) - len(rest_after_value)
        except Exception:
            try:
                value, consumed_value = cbor_decoder_factory(remaining)
            except Exception:
                try:
                    structure, consumed_fallback = decode_cbor_structure(remaining)
                except cbor_error_type:
                    try:
                        value, consumed_fallback = lenient_decode_from(remaining, 0)
                    except Exception:
                        break
                    else:
                        consumed_value = consumed_fallback
                        structure = {
                            "summary": "Decoded value (lenient)",
                            "type": type(value).__name__,
                            "value": json_safe_with_stringified_keys(value),
                            "byteLength": consumed_fallback,
                            "lenient": True,
                        }
                        predecoded_structure = structure
                else:
                    value = structure_to_value(structure)
                    consumed_value = consumed_fallback
                    predecoded_structure = structure

        if consumed_value is None or consumed_value <= 0:
            break

        try:
            if predecoded_structure is not None:
                structure = predecoded_structure
                consumed_struct = predecoded_structure.get("byteLength", consumed_value)
            else:
                structure, consumed_struct = decode_cbor_structure(remaining)
            consumed = consumed_struct
        except cbor_error_type:
            structure = {
                "summary": "Decoded value",
                "type": type(value).__name__,
                "value": json_safe_with_stringified_keys(value),
                "byteLength": consumed_value,
            }
            consumed = consumed_value
        else:
            if consumed <= 0:
                consumed = consumed_value

        if consumed <= 0:
            break

        structures.append(structure)
        values.append(value)
        consumed_total += consumed
        remaining = remaining[consumed:]

    return structures, values, consumed_total, remaining
