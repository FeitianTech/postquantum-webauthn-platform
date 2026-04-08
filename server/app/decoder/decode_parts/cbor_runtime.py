"""Extracted CBOR-sequence and CTAP repair/decode helper bodies.

These functions are executed via decode.py wrappers that rebind globals to the
facade module, preserving monkeypatch-driven behavior in tests.
"""
# pyright: reportUndefinedVariable=false
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple


def _decode_cbor_sequence(payload: bytes) -> Tuple[List[Dict[str, Any]], List[Any], int, bytes]:
    def _cbor2_decode_with_consumed(data: bytes) -> Tuple[Any, int]:
        fp = BytesIO(data)
        decoder = cbor2.CBORDecoder(fp)
        return decoder.decode(), fp.tell()

    return _decode_cbor_sequence_impl(
        payload,
        cbor_decode_from=cbor.decode_from,
        cbor_decoder_factory=_cbor2_decode_with_consumed,
        decode_cbor_structure=_decode_cbor_structure,
        structure_to_value=_structure_to_value,
        lenient_decode_from=lambda data, offset=0: _lenient_decode_from(data, offset),
        json_safe_with_stringified_keys=_json_safe_with_stringified_keys,
        cbor_error_type=_CborDecodingError,
    )


def _repair_get_assertion_entries(
    structure: Dict[str, Any],
    value: Mapping[Any, Any],
    raw_bytes: Optional[bytes] = None,
) -> Tuple[Dict[str, Any], Mapping[Any, Any], Optional[bytes]]:
    if not isinstance(value, dict):
        return structure, value, None

    entries_source = structure.get("entries")
    if isinstance(entries_source, list):
        entries = entries_source
    else:
        entries = []
        structure["entries"] = entries

    signature_entry = None
    for idx, entry in enumerate(entries):
        key_info = entry.get("key") if isinstance(entry, Mapping) else None
        if not isinstance(key_info, Mapping):
            continue
        if key_info.get("majorType") == 2 and isinstance(entry.get("value"), Mapping):
            signature_entry = (idx, entry)
            break

    signature_bytes: Optional[bytes] = None
    user_value: Optional[Any] = None

    if signature_entry is not None:
        idx, entry = signature_entry
        key_info = entry.get("key")
        if isinstance(key_info, Mapping):
            hex_value = key_info.get("hex")
            if isinstance(hex_value, str):
                try:
                    signature_bytes = bytes.fromhex(hex_value)
                except ValueError:
                    signature_bytes = None
        value_node = entry.get("value")
        if isinstance(value_node, Mapping):
            user_value = _structure_to_value(value_node)
        entries.pop(idx)

    recovered_value = dict(value)
    recovered_fields: Dict[int, Any] = {}

    if raw_bytes:
        raw_signature, raw_field_map = _extract_get_assertion_trailing_from_raw(raw_bytes)
        if raw_signature is not None:
            signature_bytes = raw_signature
        recovered_fields.update(raw_field_map)
        if user_value is None and 4 in raw_field_map:
            user_value = raw_field_map.get(4)

    if signature_bytes is None and raw_bytes:
        for raw_key, raw_value in _extract_lenient_map_entries(raw_bytes):
            if isinstance(raw_key, int) and raw_key == 3:
                candidate_bytes = _coerce_cbor_bytes(raw_value)
                if candidate_bytes is not None:
                    signature_bytes = candidate_bytes
                    break
                if isinstance(raw_value, (bytes, bytearray)):
                    signature_bytes = bytes(raw_value)
                    break
            if isinstance(raw_key, (bytes, bytearray)):
                candidate = bytes(raw_key)
                if candidate:
                    signature_bytes = candidate
                    break

    if signature_bytes is not None:
        signature_bytes, trailing_fields = _split_get_assertion_trailing_fields(signature_bytes)
        if user_value is None and 4 in trailing_fields:
            user_value = trailing_fields.pop(4)
        for key, value in trailing_fields.items():
            recovered_fields.setdefault(key, value)

        bytes_keys = [key for key in recovered_value if isinstance(key, (bytes, bytearray))]
        for key in bytes_keys:
            recovered_value.pop(key, None)
        recovered_value[3] = signature_bytes
        sig_structure, _ = _decode_cbor_structure(cbor.encode(signature_bytes))
        entries.append(
            {
                "keySummary": "3",
                "key": {"majorType": 0, "type": "unsigned", "value": 3, "summary": "3"},
                "value": sig_structure,
                "valueSummary": sig_structure.get("summary"),
            }
        )

    if user_value is not None:
        recovered_value[4] = user_value
        user_structure, _ = _decode_cbor_structure(cbor.encode(user_value))
        entries.append(
            {
                "keySummary": "4",
                "key": {"majorType": 0, "type": "unsigned", "value": 4, "summary": "4"},
                "value": user_structure,
                "valueSummary": user_structure.get("summary"),
            }
        )

    for key in sorted(recovered_fields):
        if key in {3, 4}:
            continue
        if key in recovered_value:
            continue
        field_value = recovered_fields[key]
        recovered_value[key] = field_value
        field_structure, _ = _decode_cbor_structure(cbor.encode(field_value))
        entries.append(
            {
                "keySummary": str(key),
                "key": {"majorType": 0, "type": "unsigned", "value": key, "summary": str(key)},
                "value": field_structure,
                "valueSummary": field_structure.get("summary"),
            }
        )

    structure["length"] = len(entries)
    structure["summary"] = f"map[{len(entries)}]"

    return structure, recovered_value, signature_bytes


def _try_decode_cbor(data: bytes, encoding: str) -> Optional[Dict[str, Any]]:
    if not data:
        return None

    ctap_info, payload = _extract_ctap_prefix(data)
    ctap_details = dict(ctap_info) if ctap_info is not None else None

    if not payload:
        decoded_payload: Dict[str, Any] = {
            "decodedValue": {"summary": "Empty CBOR payload", "byteLength": 0},
        }
        if ctap_details is not None:
            ctap_details["payloadLength"] = 0
            decoded_payload["ctap"] = _stringify_mapping_keys(ctap_details)
        return {
            "format": "CBOR",
            "inputEncoding": encoding,
            "decoded": decoded_payload,
            "binary": _binary_summary(data, encoding),
        }

    structures, values, consumed_total, remaining = _decode_cbor_sequence(payload)
    if not structures:
        return None

    base_structure = structures[0]
    base_value = values[0]
    primary_length = base_structure.get("byteLength") if isinstance(base_structure, Mapping) else None
    primary_bytes = payload[:primary_length] if isinstance(primary_length, int) and primary_length > 0 else None
    extra_structures = structures[1:]
    extra_values = values[1:]

    merged_signature: Optional[bytes] = None
    classification = "other"
    if isinstance(base_value, Mapping):
        base_structure, base_value, extra_structures, extra_values, merged_signature = _merge_ctap_make_credential(
            base_structure, base_value, extra_structures, extra_values
        )
        working_value: Mapping[Any, Any] = base_value

        fmt_candidate = _extract_mapping_string(working_value, (1, "1", "fmt"))
        auth_candidate = _extract_mapping_bytes(working_value, (2, "2", "authData"))

        if fmt_candidate is not None and auth_candidate is not None:
            temp_structure = dict(base_structure)
            entries = base_structure.get("entries")
            if isinstance(entries, list):
                temp_structure["entries"] = [dict(entry) for entry in entries]
            temp_value = dict(working_value)
            temp_structure, temp_value, repaired_sig = _repair_make_credential_entries(
                temp_structure, temp_value
            )
            att_stmt_candidate = _get_mapping_entry(temp_value, 3, "3", "attStmt")
            if isinstance(att_stmt_candidate, Mapping) and "sig" in att_stmt_candidate:
                classification = "make_credential_output"
                base_structure = temp_structure
                working_value = temp_value
                if repaired_sig is not None:
                    merged_signature = merged_signature or repaired_sig

                trailing_signature_result = _merge_trailing_signature(base_structure, working_value, remaining)
                if trailing_signature_result is not None:
                    base_structure, working_value, signature_bytes, remaining = trailing_signature_result
                    merged_signature = signature_bytes
                    consumed_total += len(signature_bytes)
                extra_values = []
            else:
                classification = _classify_ctap_map(working_value)
        else:
            classification = _classify_ctap_map(working_value)

        if classification == "get_assertion_output":
            base_structure, working_value, assertion_sig = _repair_get_assertion_entries(
                base_structure,
                dict(working_value),
                primary_bytes,
            )
            if assertion_sig is not None:
                merged_signature = merged_signature or assertion_sig
            extra_values = []
        elif classification == "other" and fmt_candidate is None:
            temp_structure = dict(base_structure)
            entries = base_structure.get("entries")
            if isinstance(entries, list):
                temp_structure["entries"] = [dict(entry) for entry in entries]
            temp_value = dict(working_value)
            temp_structure, temp_value, assertion_sig = _repair_get_assertion_entries(
                temp_structure,
                temp_value,
                primary_bytes,
            )
            if assertion_sig is not None:
                classification = "get_assertion_output"
                working_value = temp_value
                merged_signature = merged_signature or assertion_sig
                extra_values = []
        if classification == "other" and fmt_candidate is None and auth_candidate is not None:
            if ctap_details is not None and ctap_details.get("kind") == "status":
                classification = "get_assertion_output"

        base_value = working_value

    decoded_payload: Dict[str, Any] = {}

    expanded_json: Optional[Dict[str, Any]] = None
    ctap_decoded: Optional[Dict[str, Any]] = None
    hex_decoded_value: Optional[Any] = None

    if isinstance(base_value, Mapping):
        hex_decoded_value = _hex_json_safe(base_value)
        interpreted = _interpret_ctap_cbor_value(base_value)
        if interpreted is not None:
            ctap_decoded = _stringify_mapping_keys(_hex_json_safe(interpreted))

        if classification == "make_credential_output":
            expanded_json = _build_make_credential_expanded_json(base_value)
        elif classification == "get_assertion_output":
            expanded_json = _build_get_assertion_expanded_json(base_value, primary_bytes)
        elif classification == "make_credential_input":
            expanded_json = _build_make_credential_request_expanded_json(base_value)
        elif classification == "get_assertion_input":
            expanded_json = _build_get_assertion_request_expanded_json(base_value)
    elif base_value is not None:
        hex_decoded_value = _hex_json_safe(base_value)

    if ctap_decoded is not None:
        decoded_payload["ctapDecoded"] = ctap_decoded

    if expanded_json:
        decoded_payload["expandedJson"] = _stringify_mapping_keys(_hex_json_safe(expanded_json))

    if ctap_decoded is None and hex_decoded_value is not None:
        decoded_payload["decodedValue"] = _stringify_mapping_keys(_hex_json_safe(hex_decoded_value))

    warnings: List[str] = []

    if ctap_details is not None:
        ctap_details["payloadLength"] = consumed_total
        if merged_signature is not None:
            ctap_details["signatureLength"] = len(merged_signature)

    if extra_values:
        warnings.append(f"Detected {len(extra_values)} additional CBOR object(s) following the primary payload.")

    trailing = remaining
    ignored_padding = 0
    if trailing:
        if _is_padding_bytes(trailing):
            ignored_padding = len(trailing)
        else:
            warnings.append(f"Trailing {len(trailing)} byte(s) after CBOR payload.")

    if ctap_details is not None:
        if ignored_padding:
            ctap_details["ignoredPaddingBytes"] = ignored_padding
        if trailing and not _is_padding_bytes(trailing):
            ctap_details["trailingBytesHex"] = trailing.hex()
        decoded_payload["ctap"] = _stringify_mapping_keys(ctap_details)

    result: Dict[str, Any] = {
        "format": "CBOR",
        "inputEncoding": encoding,
        "decoded": decoded_payload,
        "binary": _binary_summary(data, encoding),
    }
    if warnings:
        result["malformed"] = warnings
    return result
