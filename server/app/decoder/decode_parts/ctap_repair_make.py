"""CTAP make-credential and shared repair leaf helpers."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from fido2 import cbor
from fido2.webauthn import AuthenticatorData

from .cbor_core import _decode_cbor_structure
from .key_utils import MISSING, coerce_cbor_bytes as _coerce_cbor_bytes, get_mapping_entry as _get_mapping_entry


def _merge_ctap_make_credential(
    structure: Dict[str, Any],
    value: Mapping[Any, Any],
    extra_structures: List[Dict[str, Any]],
    extra_values: List[Any],
) -> Tuple[Dict[str, Any], Mapping[Any, Any], List[Dict[str, Any]], List[Any], Optional[bytes]]:
    signature_bytes: Optional[bytes] = None

    if isinstance(value, Mapping) and value.get("al&") == "sig":
        normalized_value = dict(value)
        normalized_value.pop("al&", None)

        def _extract_alg(mapping: Mapping[Any, Any]) -> Optional[int]:
            for key in ("alg", "algorithm", 1, "1", 3, "3"):
                raw = mapping.get(key)
                if isinstance(raw, int):
                    return raw
            return None

        def _extract_sig(mapping: Mapping[Any, Any]) -> Optional[bytes]:
            for key in ("sig", "signature", 2, "2", 3, "3"):
                if key in mapping:
                    coerced = _coerce_cbor_bytes(mapping[key])
                    if coerced is not None:
                        return coerced
            return None

        alg_value = _extract_alg(normalized_value)
        truncated_sig = _coerce_cbor_bytes(normalized_value.pop("sig", None))
        if truncated_sig is None:
            truncated_sig = _coerce_cbor_bytes(normalized_value.pop("signature", None))
        normalized_value.pop("alg", None)
        normalized_value.pop("algorithm", None)
        normalized_value.pop("attStmt", None)
        normalized_value.pop("attstmt", None)

        att_structure_override: Optional[Dict[str, Any]] = None
        att_stmt_base: Optional[Mapping[Any, Any]] = None

        if extra_values:
            candidate = extra_values[0]
            if isinstance(candidate, Mapping):
                candidate_alg = _extract_alg(candidate)
                candidate_sig = _extract_sig(candidate)
                if candidate_alg is not None or candidate_sig is not None:
                    alg_value = candidate_alg if candidate_alg is not None else alg_value
                    if candidate_sig is not None:
                        signature_bytes = candidate_sig
                    att_stmt_base = candidate
                    extra_values = extra_values[1:]
                    if extra_structures:
                        att_structure_override = extra_structures[0]
                        extra_structures = extra_structures[1:]
            elif isinstance(candidate, (bytes, bytearray, memoryview)):
                signature_bytes = _coerce_cbor_bytes(candidate)
                extra_values = extra_values[1:]
                if extra_structures:
                    extra_structures = extra_structures[1:]

        if signature_bytes is None:
            signature_bytes = truncated_sig

        if signature_bytes is not None:
            if alg_value is None:
                alg_value = -7

            if att_stmt_base is not None:
                att_stmt = dict(att_stmt_base)
                att_stmt.pop("sig", None)
                att_stmt.pop("signature", None)
                att_stmt.pop("alg", None)
                att_stmt.pop("algorithm", None)
                att_stmt["alg"] = alg_value
                att_stmt["sig"] = signature_bytes
            else:
                att_stmt = {"alg": alg_value, "sig": signature_bytes}
            normalized_value[3] = att_stmt

            if isinstance(att_structure_override, Mapping):
                att_structure = att_structure_override
            else:
                att_structure, _ = _decode_cbor_structure(cbor.encode(att_stmt))

            entries = structure.get("entries")
            if isinstance(entries, list) and entries:
                entries[-1] = {
                    "keySummary": "3",
                    "key": {"majorType": 0, "type": "unsigned", "value": 3, "summary": "3"},
                    "value": att_structure,
                    "valueSummary": att_structure.get("summary") if isinstance(att_structure, Mapping) else None,
                }
            structure["length"] = len(entries) if isinstance(entries, list) else structure.get("length", 3)
            value = normalized_value
            return structure, value, extra_structures, extra_values, signature_bytes

    return structure, value, extra_structures, extra_values, None


def _repair_make_credential_entries(
    structure: Dict[str, Any],
    value: Mapping[Any, Any],
    *,
    default_alg: int = -50,
) -> Tuple[Dict[str, Any], Mapping[Any, Any], Optional[bytes]]:
    if not isinstance(value, dict):
        return structure, value, None

    signature_key = None
    entries = structure.get("entries")
    if isinstance(entries, list):
        for idx, entry in enumerate(entries):
            key_info = entry.get("key") if isinstance(entry, Mapping) else None
            if not isinstance(key_info, Mapping):
                continue
            major_type = key_info.get("majorType")
            if major_type in {2, 7} or (major_type == 0 and key_info.get("value") == 13):
                signature_key = key_info
                entries.pop(idx)
                break

    signature_bytes: Optional[bytes] = None
    if signature_key is not None:
        hex_value = signature_key.get("hex")
        if isinstance(hex_value, str):
            try:
                signature_bytes = bytes.fromhex(hex_value)
            except ValueError:
                signature_bytes = None

    polished_value = dict(value)
    pop_keys: List[Any] = []
    for key in list(polished_value.keys()):
        if isinstance(key, (bytes, bytearray)):
            pop_keys.append(key)
    for key in pop_keys:
        polished_value.pop(key, None)

    if 13 in polished_value and 3 not in polished_value:
        raw_entry = polished_value.pop(13)
        if isinstance(raw_entry, list):
            segments: List[bytes] = []
            alg_candidate: Optional[int] = None
            for item in raw_entry:
                if isinstance(item, (bytes, bytearray)):
                    segments.append(bytes(item))
                elif isinstance(item, Mapping) and alg_candidate is None:
                    for possible in item.values():
                        if isinstance(possible, int):
                            alg_candidate = possible
                            break
            if segments:
                signature_bytes = b"".join(segments)
                if alg_candidate is not None:
                    default_alg = alg_candidate

    if signature_bytes is not None:
        polished_value[3] = {"sig": signature_bytes, "alg": default_alg}
        att_stmt_structure, _ = _decode_cbor_structure(
            cbor.encode({"sig": signature_bytes, "alg": default_alg})
        )
        if isinstance(entries, list):
            entries.append(
                {
                    "keySummary": "3",
                    "key": {"majorType": 0, "type": "unsigned", "value": 3, "summary": "3"},
                    "value": att_stmt_structure,
                    "valueSummary": att_stmt_structure.get("summary"),
                }
            )
            structure["length"] = len(entries)
            structure["summary"] = f"map[{len(entries)}]"

    return structure, polished_value, signature_bytes


def _derive_alg_from_auth_data(auth_data_bytes: Optional[bytes]) -> Optional[int]:
    if not auth_data_bytes:
        return None
    try:
        auth_data = AuthenticatorData(auth_data_bytes)
    except Exception:
        return None

    credential = getattr(auth_data, "credential_data", None)
    if credential is None:
        return None

    public_key = getattr(credential, "public_key", None)
    alg_value = getattr(public_key, "alg", None)
    return alg_value if isinstance(alg_value, int) else None


def _merge_trailing_signature(
    structure: Dict[str, Any],
    value: Mapping[Any, Any],
    trailing: bytes,
) -> Optional[Tuple[Dict[str, Any], Mapping[Any, Any], bytes, bytes]]:
    if not trailing or all(byte in (0x00, 0xFF) for byte in trailing):
        return None

    fmt_entry = _get_mapping_entry(value, 1, "1", "fmt")
    fmt = fmt_entry if fmt_entry is not MISSING else None
    if fmt != "packed":
        return None

    if _get_mapping_entry(value, 3, "3", "signature") is not MISSING:
        return None

    if not isinstance(structure, Mapping):
        return None

    auth_data_entry = _get_mapping_entry(value, 2, "2", "authData")
    auth_data_bytes = _coerce_cbor_bytes(auth_data_entry)
    alg_value = _derive_alg_from_auth_data(auth_data_bytes)
    signature_bytes = bytes(trailing)

    att_stmt: Dict[str, Any] = {"sig": signature_bytes}
    if alg_value is not None:
        att_stmt["alg"] = alg_value

    att_structure, _ = _decode_cbor_structure(cbor.encode(att_stmt))

    updated_structure = dict(structure)
    entries_source = structure.get("entries")
    entries: List[Dict[str, Any]] = (
        list(entries_source) if isinstance(entries_source, list) else []
    )
    entries.append(
        {
            "keySummary": "3",
            "key": {"majorType": 0, "type": "unsigned", "value": 3, "summary": "3"},
            "value": att_structure,
            "valueSummary": att_structure.get("summary") if isinstance(att_structure, Mapping) else None,
        }
    )
    updated_structure["entries"] = entries
    updated_structure["length"] = len(entries)
    updated_structure["summary"] = f"map[{len(entries)}]"

    updated_value = dict(value)
    updated_value[3] = att_stmt

    return updated_structure, updated_value, signature_bytes, b""


def _extract_mapping_string(value: Mapping[Any, Any], keys: Iterable[Any]) -> Optional[str]:
    if not isinstance(value, Mapping):
        return None
    candidate = _get_mapping_entry(value, *keys)
    if candidate is MISSING:
        return None
    if isinstance(candidate, str):
        stripped = candidate.strip()
        if stripped:
            return stripped
    return None


def _extract_mapping_bytes(value: Mapping[Any, Any], keys: Iterable[Any]) -> Optional[bytes]:
    if not isinstance(value, Mapping):
        return None
    candidate = _get_mapping_entry(value, *keys)
    if candidate is MISSING:
        return None
    candidate_bytes = _coerce_cbor_bytes(candidate)
    if candidate_bytes is not None:
        return candidate_bytes
    return None
