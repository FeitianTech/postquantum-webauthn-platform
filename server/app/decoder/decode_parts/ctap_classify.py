"""CTAP map labeling and shape-classification helpers."""
from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional, Sequence

from .ctap_repair_leaf import _extract_mapping_bytes, _extract_mapping_string
from .key_utils import MISSING, coerce_cbor_bytes as _coerce_cbor_bytes, get_mapping_entry as _get_mapping_entry, hex_json_safe as _hex_json_safe

_MAKE_CREDENTIAL_REQUEST_LABELS: Dict[Any, str] = {
    1: "clientDataHash",
    "clientDataHash": "clientDataHash",
    2: "rp",
    "rp": "rp",
    3: "user",
    "user": "user",
    4: "pubKeyCredParams",
    "pubKeyCredParams": "pubKeyCredParams",
    5: "excludeList",
    "excludeList": "excludeList",
    6: "extensions",
    "extensions": "extensions",
    7: "options",
    "options": "options",
    8: "pinUvAuthParam",
    "pinUvAuthParam": "pinUvAuthParam",
    9: "pinUvAuthProtocol",
    "pinUvAuthProtocol": "pinUvAuthProtocol",
    10: "enterpriseAttestation",
    "enterpriseAttestation": "enterpriseAttestation",
    11: "largeBlobKey",
    "largeBlobKey": "largeBlobKey",
}

_GET_ASSERTION_REQUEST_LABELS: Dict[Any, str] = {
    1: "rpId",
    "rpId": "rpId",
    2: "clientDataHash",
    "clientDataHash": "clientDataHash",
    3: "allowList",
    "allowList": "allowList",
    4: "extensions",
    "extensions": "extensions",
    5: "options",
    "options": "options",
    6: "pinUvAuthParam",
    "pinUvAuthParam": "pinUvAuthParam",
    7: "pinUvAuthProtocol",
    "pinUvAuthProtocol": "pinUvAuthProtocol",
    8: "largeBlobKey",
    "largeBlobKey": "largeBlobKey",
}

_MAKE_CREDENTIAL_RESPONSE_LABELS: Dict[Any, str] = {
    1: "fmt",
    "fmt": "fmt",
    2: "authData",
    "authData": "authData",
    3: "attStmt",
    "attStmt": "attStmt",
    4: "epAtt",
    "epAtt": "epAtt",
    5: "largeBlobKey",
    "largeBlobKey": "largeBlobKey",
    6: "extensions",
    "extensions": "extensions",
}

_GET_ASSERTION_RESPONSE_LABELS: Dict[Any, str] = {
    1: "credential",
    "credential": "credential",
    2: "authData",
    "authData": "authData",
    3: "signature",
    "signature": "signature",
    4: "user",
    "user": "user",
    5: "numberOfCredentials",
    "numberOfCredentials": "numberOfCredentials",
    6: "userSelected",
    "userSelected": "userSelected",
    7: "largeBlobKey",
    "largeBlobKey": "largeBlobKey",
    8: "extensions",
    "extensions": "extensions",
}


def _resolve_ctap_label(label_map: Mapping[Any, str], key: Any) -> Optional[str]:
    if key in label_map:
        return label_map[key]
    key_str = str(key)
    if key_str in label_map:
        return label_map[key_str]
    return None


def _format_ctap_entry_key(key: Any, label: Optional[str]) -> str:
    if isinstance(key, (bytes, bytearray)):
        key_display = bytes(key).hex()
    else:
        key_display = str(key)
    if label:
        return f"{key_display} ({label})"
    return key_display


def _build_labeled_ctap_map(
    mapping: Mapping[Any, Any],
    labels: Mapping[Any, str],
    handlers: Mapping[Any, Callable[[Any], Any]],
    *,
    missing_keys: Sequence[Any] = (),
) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    seen_keys: set = set()
    seen_labels: set = set()

    if isinstance(mapping, Mapping):
        for key in mapping:
            label = _resolve_ctap_label(labels, key)
            formatted_key = _format_ctap_entry_key(key, label)
            handler: Optional[Callable[[Any], Any]] = None
            if label is not None and label in handlers:
                handler = handlers[label]
            elif key in handlers:
                handler = handlers[key]
            elif str(key) in handlers:
                handler = handlers[str(key)]
            value = mapping[key]
            if handler is not None:
                result[formatted_key] = handler(value)
            else:
                result[formatted_key] = _hex_json_safe(value)
            seen_keys.add(key)
            seen_keys.add(str(key))
            if label is not None:
                seen_labels.add(label)

    for missing in missing_keys:
        label = _resolve_ctap_label(labels, missing)
        if missing in seen_keys or str(missing) in seen_keys:
            continue
        if label is not None and label in seen_labels:
            continue
        formatted_key = _format_ctap_entry_key(missing, label)
        handler: Optional[Callable[[Any], Any]] = None
        if label is not None and label in handlers:
            handler = handlers[label]
        elif missing in handlers:
            handler = handlers[missing]
        elif str(missing) in handlers:
            handler = handlers[str(missing)]
        if handler is not None:
            result.setdefault(formatted_key, handler(None))
        else:
            result.setdefault(formatted_key, None)

    return result


def _looks_like_make_credential_request(value: Mapping[Any, Any]) -> bool:
    client_hash_entry = _get_mapping_entry(value, 1, "1", "clientDataHash")
    client_hash_bytes = _coerce_cbor_bytes(client_hash_entry)
    if client_hash_bytes is None:
        return False
    if _extract_mapping_string(value, (1, "1", "fmt")) is not None:
        return False
    if _extract_mapping_bytes(value, (2, "2", "authData")) is not None:
        return False
    rp_entry = _get_mapping_entry(value, 2, "2", "rp")
    user_entry = _get_mapping_entry(value, 3, "3", "user")
    if rp_entry is MISSING or user_entry is MISSING:
        return False
    return True


def _looks_like_get_assertion_request(value: Mapping[Any, Any]) -> bool:
    if not isinstance(value, Mapping):
        return False
    rp_candidate = value.get(1, MISSING)
    if isinstance(rp_candidate, str) and rp_candidate.strip():
        pass
    else:
        rp_candidate = value.get("rpId", MISSING)
        if not isinstance(rp_candidate, str) or not rp_candidate.strip():
            return False
    client_entry = value.get(2, MISSING)
    if client_entry is MISSING:
        client_entry = value.get("clientDataHash", MISSING)
    if client_entry is MISSING or _coerce_cbor_bytes(client_entry) is None:
        return False
    signature_candidate = value.get(3, MISSING)
    if signature_candidate is MISSING:
        signature_candidate = value.get("signature", MISSING)
    if signature_candidate is not MISSING and _coerce_cbor_bytes(signature_candidate) is not None:
        return False
    auth_candidate = value.get("authData", MISSING)
    if auth_candidate is not MISSING and _coerce_cbor_bytes(auth_candidate) is not None:
        return False
    return True


def _looks_like_make_credential_output(value: Mapping[Any, Any]) -> bool:
    fmt_value = _extract_mapping_string(value, (1, "1", "fmt"))
    auth_data_bytes = _extract_mapping_bytes(value, (2, "2", "authData"))
    att_stmt_value = _get_mapping_entry(value, 3, "3", "attStmt")
    if att_stmt_value is MISSING:
        att_stmt_value = None
    att_stmt_bytes = _coerce_cbor_bytes(att_stmt_value)
    att_stmt_map = att_stmt_value if isinstance(att_stmt_value, Mapping) else None
    return fmt_value is not None and auth_data_bytes is not None and (
        att_stmt_map is not None or att_stmt_bytes is not None
    )


def _looks_like_get_assertion_output(value: Mapping[Any, Any]) -> bool:
    auth_data_bytes = _extract_mapping_bytes(value, (2, "2", "authData"))
    signature_bytes = _extract_mapping_bytes(value, (3, "3", "signature"))
    return auth_data_bytes is not None and signature_bytes is not None


def _classify_ctap_map(value: Mapping[Any, Any]) -> str:
    if _looks_like_make_credential_output(value):
        return "make_credential_output"
    if _looks_like_get_assertion_output(value):
        return "get_assertion_output"
    if _looks_like_make_credential_request(value):
        return "make_credential_input"
    if _looks_like_get_assertion_request(value):
        return "get_assertion_input"
    return "other"
