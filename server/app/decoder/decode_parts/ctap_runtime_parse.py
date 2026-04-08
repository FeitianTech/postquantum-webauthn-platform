"""Extracted CTAP parsing and conversion helper function bodies.

These functions are executed via decode.py wrappers that rebind globals to the
facade module, preserving monkeypatch-driven behavior in tests.
"""
# pyright: reportUndefinedVariable=false
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


def _convert_ctap_allow_list(entry: Any) -> Any:
    if isinstance(entry, Sequence) and not isinstance(entry, (str, bytes, bytearray)):
        return [_convert_ctap_credential_descriptor(item) for item in entry]
    return _convert_optional_ctap_field(entry)


def _convert_pub_key_cred_params(entry: Any) -> Any:
    if isinstance(entry, Sequence) and not isinstance(entry, (str, bytes, bytearray)):
        return [_hex_json_safe(item) for item in entry]
    return _hex_json_safe(entry)


def _convert_auth_data_field(value: Any) -> Any:
    auth_bytes = _coerce_cbor_bytes(value)
    if auth_bytes is not None:
        auth_info, trailing = _format_auth_data_for_expanded_json(auth_bytes)
        if trailing:
            auth_info = dict(auth_info)
        return auth_info
    return _convert_optional_ctap_field(value)


def _convert_signature_field(value: Any) -> Any:
    signature_bytes = _coerce_cbor_bytes(value)
    if signature_bytes is not None:
        return signature_bytes.hex()
    if value is None:
        return None
    return _convert_optional_ctap_field(value)


def _convert_att_stmt_field(value: Any) -> Any:
    if value is None:
        return None
    return _format_att_stmt_for_expanded_json(value)


def _convert_ctap_user_field(value: Any) -> Any:
    if value is None:
        return None
    return _convert_ctap_user(value)


def _summarize_bytes_for_json(data: bytes) -> Dict[str, Any]:
    return {
        "length": len(data),
        "hex": data.hex(),
        "base64": base64.b64encode(data).decode("ascii"),
        "base64url": encode_base64url(data),
    }


def _parse_authenticator_data_bytes(data: bytes) -> Tuple[Dict[str, Any], bytes, bytes]:
    details: Dict[str, Any] = {}
    if len(data) < 37:
        details["parseError"] = "Authenticator data shorter than minimum header."
        return details, data, b""

    offset = 0
    rp_id_hash = data[offset : offset + 32]
    offset += 32
    flags_byte = data[offset]
    offset += 1
    sign_count = int.from_bytes(data[offset : offset + 4], "big")
    offset += 4

    details["rpIdHash"] = rp_id_hash.hex()
    details["flags"] = {
        "value": flags_byte,
        "bitfield": f"0b{flags_byte:08b}",
        "UP": bool(flags_byte & AuthenticatorData.FLAG.UP),
        "UV": bool(flags_byte & AuthenticatorData.FLAG.UV),
        "BE": bool(flags_byte & AuthenticatorData.FLAG.BE),
        "BS": bool(flags_byte & AuthenticatorData.FLAG.BS),
        "AT": bool(flags_byte & AuthenticatorData.FLAG.AT),
        "ED": bool(flags_byte & AuthenticatorData.FLAG.ED),
    }
    details["signCount"] = sign_count

    def _decode_cbor_item(buffer: bytes) -> Tuple[Any, int]:
        value, consumed = _lenient_decode_from(buffer, 0)
        return value, consumed

    at_flag = bool(flags_byte & AuthenticatorData.FLAG.AT)
    ed_flag = bool(flags_byte & AuthenticatorData.FLAG.ED)

    attested_trailing = b""
    if at_flag:
        attested: Dict[str, Any] = {}
        remaining = len(data) - offset
        if remaining < 18:
            attested["parseError"] = "Attested credential data truncated."
            offset = len(data)
        else:
            aaguid = data[offset : offset + 16]
            offset += 16
            declared_len = int.from_bytes(data[offset : offset + 2], "big")
            offset += 2
            remaining = len(data) - offset
            actual_len = min(declared_len, remaining if remaining >= 0 else 0)
            credential_id = data[offset : offset + actual_len]
            offset += actual_len

            attested["aaguid"] = aaguid.hex()
            attested["credentialIdDeclaredLength"] = declared_len
            attested["credentialIdActualLength"] = actual_len
            attested["credentialId"] = credential_id.hex()
            if actual_len != declared_len:
                attested["lengthMismatch"] = True

            cose_raw = data[offset:]
            if cose_raw:
                try:
                    cose_value, consumed = _decode_cbor_item(cose_raw)
                except Exception:
                    cose_value, consumed = None, 0
                if consumed > 0:
                    offset += consumed
                    if isinstance(cose_value, Mapping):
                        attested["credentialPublicKey"] = _hex_json_safe(cose_value)
                    else:
                        attested["credentialPublicKey"] = _hex_json_safe(cose_value)
                    attested_trailing = cose_raw[consumed:]
                else:
                    attested["credentialPublicKey"] = cose_raw.hex()
                    offset = len(data)
            details["attestedCredentialData"] = attested

    extensions_trailing = b""
    if ed_flag and offset < len(data):
        try:
            ext_value, consumed = _decode_cbor_item(data[offset:])
        except Exception:
            ext_value, consumed = None, 0
        if consumed > 0:
            offset += consumed
            if isinstance(ext_value, Mapping):
                details["extensions"] = _hex_json_safe(ext_value)
            else:
                details["extensions"] = _hex_json_safe(ext_value)
            extensions_trailing = data[offset:]
        else:
            extensions_trailing = data[offset:]
            offset = len(data)

    trimmed = data[:offset]
    trailing = b"".join(part for part in [attested_trailing, extensions_trailing, data[offset:]] if part)
    return details, trimmed, trailing


def _format_auth_data_for_expanded_json(auth_data_bytes: bytes) -> Tuple[Dict[str, Any], bytes]:
    details, trimmed, trailing = _parse_authenticator_data_bytes(auth_data_bytes)
    formatted: Dict[str, Any] = dict(details)
    formatted.setdefault("raw", trimmed.hex())
    if trailing:
        formatted["trailingBytesHex"] = trailing.hex()
    return formatted, trailing


def _format_att_stmt_for_expanded_json(att_stmt: Any) -> Dict[str, Any]:
    formatted: Dict[str, Any] = {}

    if isinstance(att_stmt, Mapping):
        for key, value in att_stmt.items():
            if key == "sig":
                sig_bytes = _coerce_cbor_bytes(value)
                if sig_bytes is not None:
                    formatted["sig"] = sig_bytes.hex()
                else:
                    formatted["sig"] = _hex_json_safe(value)
            elif key == "x5c":
                formatted["x5c"] = _convert_certificate_chain(value)
            else:
                formatted[key] = _hex_json_safe(value)
        return formatted

    sig_bytes = _coerce_cbor_bytes(att_stmt)
    if sig_bytes is not None:
        formatted["sig"] = sig_bytes.hex()
    elif att_stmt is not None:
        formatted["value"] = _hex_json_safe(att_stmt)

    return formatted


def _decode_trailing_map(data: bytes) -> Dict[Any, Any]:
    mapping: Dict[Any, Any] = {}
    offset = 0
    while offset < len(data):
        key, new_offset = _lenient_decode_from(data, offset)
        if new_offset <= offset:
            break
        offset = new_offset
        value, new_offset = _lenient_decode_from(data, offset)
        if new_offset <= offset:
            break
        offset = new_offset
        try:
            mapping[key] = value
        except TypeError:
            mapping[str(key)] = value
    return mapping


def _extract_lenient_map_entries(raw_bytes: Optional[bytes]) -> List[Tuple[Any, Any]]:
    entries: List[Tuple[Any, Any]] = []
    if not raw_bytes:
        return entries
    offset = 0
    initial = raw_bytes[offset]
    major_type = initial >> 5
    if major_type != 5:
        return entries
    info = initial & 0x1F
    offset += 1
    length, offset = _lenient_read_uint(info, raw_bytes, offset)
    for _ in range(length):
        key, new_offset = _lenient_decode_from(raw_bytes, offset)
        if new_offset <= offset:
            break
        offset = new_offset
        value, new_offset = _lenient_decode_from(raw_bytes, offset)
        if new_offset <= offset:
            entries.append((key, None))
            break
        offset = new_offset
        entries.append((key, value))
        if offset >= len(raw_bytes):
            break
    return entries


def _extract_signature_from_raw_bytes(raw_bytes: bytes) -> Optional[bytes]:
    if not raw_bytes:
        return None
    hex_data = raw_bytes.hex()
    for prefix, length_hex_len in ("0358", 2), ("0359", 4), ("035a", 8), ("035b", 16):
        idx = hex_data.find(prefix)
        if idx == -1:
            continue
        length_hex = hex_data[idx + 4 : idx + 4 + length_hex_len]
        if len(length_hex) != length_hex_len:
            continue
        length = int(length_hex, 16)
        start = idx + 4 + length_hex_len
        end = start + length * 2
        if end > len(hex_data):
            continue
        try:
            return bytes.fromhex(hex_data[start:end])
        except ValueError:
            continue
    return None


def _convert_user_text_value(value: Any) -> Any:
    if isinstance(value, str):
        return value

    data_bytes = _coerce_cbor_bytes(value)
    if data_bytes is None:
        return _hex_json_safe(value)

    text_value = _try_decode_utf8(data_bytes)
    binary_summary = _binary_summary(
        data_bytes, "utf-8" if text_value is not None else "binary"
    )
    if text_value is None:
        return binary_summary

    return {"text": text_value, "binary": binary_summary}


def _convert_ctap_user(entry: Any) -> Any:
    data_bytes = _coerce_cbor_bytes(entry)
    if data_bytes is not None:
        decoded_map = _attempt_decode_cbor_map(data_bytes)
        if decoded_map is not None:
            return _convert_ctap_user(decoded_map)
        return data_bytes.hex()

    if isinstance(entry, str):
        try:
            decoded_value, _ = _decode_binary_input(entry)
        except ValueError:
            decoded_value = None
        if decoded_value:
            decoded_map = _attempt_decode_cbor_map(decoded_value)
            if decoded_map is not None:
                return _convert_ctap_user(decoded_map)

    if not isinstance(entry, Mapping):
        return _hex_json_safe(entry)

    normalized_entry = _normalize_user_mapping(entry)

    user: Dict[str, Any] = {}
    id_value = _get_mapping_entry(normalized_entry, "id", 1)
    if id_value is not _MISSING:
        id_bytes = _coerce_cbor_bytes(id_value)
        if id_bytes is not None:
            user["id"] = id_bytes.hex()

    name_value = _get_mapping_entry(normalized_entry, "name", 2)
    if name_value is not _MISSING:
        user["name"] = _convert_user_text_value(name_value)

    display_name_value = _get_mapping_entry(normalized_entry, "displayName", 3)
    if display_name_value is not _MISSING:
        user["displayName"] = _convert_user_text_value(display_name_value)

    icon_value = _get_mapping_entry(normalized_entry, "icon", 4)
    if icon_value is not _MISSING:
        user["icon"] = _convert_user_text_value(icon_value)

    for key in normalized_entry:
        if key in {"id", "name", "displayName", "icon"} or key in {1, 2, 3, 4}:
            continue
        user[str(key)] = _hex_json_safe(normalized_entry[key])

    return user
