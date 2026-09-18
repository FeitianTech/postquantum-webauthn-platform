"""CTAP interpretation and expanded-JSON helpers."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from ...encoding import decode_hex
from . import ctap_classify, ctap_runtime_parse, result_runtime
from .ctap_convert_leaf import (
    _convert_ctap_credential_descriptor,
    _convert_optional_ctap_field,
)
from .keys import MISSING as _MISSING
from .keys import coerce_cbor_bytes as _coerce_cbor_bytes
from .keys import get_mapping_entry as _get_mapping_entry
from .keys import hex_json_safe as _hex_json_safe

# The converter tables the labelled-map builder dispatches through.
#
# The ``ctap_runtime_parse`` entries go through a lambda rather than holding the
# function object: this module and ``ctap_runtime_parse`` import each other, so
# that module can still be partially initialised when this table is built, and
# resolving on every call is also what keeps a patch on the defining module
# visible here.
_MAKE_CREDENTIAL_REQUEST_HANDLERS: dict[Any, Callable[[Any], Any]] = {
    "clientDataHash": _convert_optional_ctap_field,
    "rp": _hex_json_safe,
    "user": lambda value: ctap_runtime_parse._convert_ctap_user_field(value),
    "pubKeyCredParams": lambda value: ctap_runtime_parse._convert_pub_key_cred_params(value),
    "excludeList": lambda value: ctap_runtime_parse._convert_ctap_allow_list(value),
    "extensions": _hex_json_safe,
    "options": _hex_json_safe,
    "pinUvAuthParam": _convert_optional_ctap_field,
    "pinUvAuthProtocol": _hex_json_safe,
    "enterpriseAttestation": _hex_json_safe,
    "largeBlobKey": _convert_optional_ctap_field,
}

_GET_ASSERTION_REQUEST_HANDLERS: dict[Any, Callable[[Any], Any]] = {
    "rpId": _hex_json_safe,
    "clientDataHash": _convert_optional_ctap_field,
    "allowList": lambda value: ctap_runtime_parse._convert_ctap_allow_list(value),
    "extensions": _hex_json_safe,
    "options": _hex_json_safe,
    "pinUvAuthParam": _convert_optional_ctap_field,
    "pinUvAuthProtocol": _hex_json_safe,
    "largeBlobKey": _convert_optional_ctap_field,
}

_MAKE_CREDENTIAL_RESPONSE_HANDLERS: dict[Any, Callable[[Any], Any]] = {
    "fmt": _hex_json_safe,
    "authData": lambda value: ctap_runtime_parse._convert_auth_data_field(value),
    "attStmt": lambda value: ctap_runtime_parse._convert_att_stmt_field(value),
    "epAtt": _convert_optional_ctap_field,
    "largeBlobKey": _convert_optional_ctap_field,
    "extensions": _convert_optional_ctap_field,
}

_GET_ASSERTION_RESPONSE_HANDLERS: dict[Any, Callable[[Any], Any]] = {
    "credential": _convert_ctap_credential_descriptor,
    "authData": lambda value: ctap_runtime_parse._convert_auth_data_field(value),
    "signature": lambda value: ctap_runtime_parse._convert_signature_field(value),
    "user": lambda value: ctap_runtime_parse._convert_ctap_user_field(value),
    "numberOfCredentials": _convert_optional_ctap_field,
    "userSelected": _convert_optional_ctap_field,
    "largeBlobKey": _convert_optional_ctap_field,
    "extensions": _convert_optional_ctap_field,
}


def _build_make_credential_request_expanded_json(
    value: Mapping[Any, Any]
) -> dict[str, Any]:
    return ctap_classify._build_labeled_ctap_map(
        value,
        ctap_classify._MAKE_CREDENTIAL_REQUEST_LABELS,
        _MAKE_CREDENTIAL_REQUEST_HANDLERS,
    )


def _build_get_assertion_request_expanded_json(
    value: Mapping[Any, Any]
) -> dict[str, Any]:
    return ctap_classify._build_labeled_ctap_map(
        value,
        ctap_classify._GET_ASSERTION_REQUEST_LABELS,
        _GET_ASSERTION_REQUEST_HANDLERS,
    )


def _build_make_credential_expanded_json(value: Mapping[Any, Any]) -> dict[str, Any]:
    return ctap_classify._build_labeled_ctap_map(
        value,
        ctap_classify._MAKE_CREDENTIAL_RESPONSE_LABELS,
        _MAKE_CREDENTIAL_RESPONSE_HANDLERS,
    )


def _build_get_assertion_expanded_json(value: Mapping[Any, Any], raw_bytes: bytes | None = None) -> dict[str, Any]:
    result = ctap_classify._build_labeled_ctap_map(
        value,
        ctap_classify._GET_ASSERTION_RESPONSE_LABELS,
        _GET_ASSERTION_RESPONSE_HANDLERS,
        missing_keys=(3,),
    )

    signature_key = ctap_classify._format_ctap_entry_key(3, ctap_classify._resolve_ctap_label(ctap_classify._GET_ASSERTION_RESPONSE_LABELS, 3))
    auth_key = ctap_classify._format_ctap_entry_key(2, ctap_classify._resolve_ctap_label(ctap_classify._GET_ASSERTION_RESPONSE_LABELS, 2))
    auth_details = result.get(auth_key)
    auth_trailing_bytes: bytes | None = None
    if isinstance(auth_details, Mapping):
        trailing_hex = auth_details.get("trailingBytesHex")
        if isinstance(trailing_hex, str) and trailing_hex.strip():
            try:
                auth_trailing_bytes = decode_hex(trailing_hex)
            except ValueError:
                auth_trailing_bytes = None

    if result.get(signature_key) is None and auth_trailing_bytes:
        trailing_map = ctap_runtime_parse._decode_trailing_map(auth_trailing_bytes)
        sig_entry = trailing_map.pop(3, None)
        if sig_entry is not None:
            sig_bytes = _coerce_cbor_bytes(sig_entry)
            if sig_bytes is not None:
                result[signature_key] = sig_bytes.hex()
        user_entry_trailing = trailing_map.pop(4, None)
        if user_entry_trailing is not None:
            user_key = ctap_classify._format_ctap_entry_key(4, ctap_classify._resolve_ctap_label(ctap_classify._GET_ASSERTION_RESPONSE_LABELS, 4))
            result[user_key] = ctap_runtime_parse._convert_ctap_user(user_entry_trailing)
        number_entry = trailing_map.pop(5, None)
        if number_entry is not None:
            number_key = ctap_classify._format_ctap_entry_key(5, ctap_classify._resolve_ctap_label(ctap_classify._GET_ASSERTION_RESPONSE_LABELS, 5))
            result[number_key] = _convert_optional_ctap_field(number_entry)
        user_selected_entry = trailing_map.pop(6, None)
        if user_selected_entry is not None:
            selected_key = ctap_classify._format_ctap_entry_key(6, ctap_classify._resolve_ctap_label(ctap_classify._GET_ASSERTION_RESPONSE_LABELS, 6))
            result[selected_key] = _convert_optional_ctap_field(user_selected_entry)
        extensions_entry = trailing_map.pop(8, None)
        if extensions_entry is not None:
            extensions_key = ctap_classify._format_ctap_entry_key(8, ctap_classify._resolve_ctap_label(ctap_classify._GET_ASSERTION_RESPONSE_LABELS, 8))
            result[extensions_key] = _convert_optional_ctap_field(extensions_entry)
        if trailing_map:
            result["trailingFields"] = {str(k): _hex_json_safe(v) for k, v in trailing_map.items()}

    if result.get(signature_key) is None and raw_bytes:
        sig_bytes = ctap_runtime_parse._extract_signature_from_raw_bytes(raw_bytes)
        if sig_bytes is not None:
            result[signature_key] = sig_bytes.hex()

    return result


def _interpret_ctap_cbor_value(value: Any) -> dict[str, Any] | None:
    if isinstance(value, Mapping):
        interpreted = _interpret_make_credential_map(value)
        if interpreted is not None:
            return {"makeCredentialResponse": interpreted}
        interpreted = _interpret_get_assertion_map(value)
        if interpreted is not None:
            return {"getAssertionResponse": interpreted}
        interpreted = _interpret_make_credential_request_map(value)
        if interpreted is not None:
            return {"makeCredentialRequest": interpreted}
        interpreted = _interpret_get_assertion_request_map(value)
        if interpreted is not None:
            return {"getAssertionRequest": interpreted}
    return None


def _interpret_make_credential_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    fmt = _get_mapping_entry(value, 1, "1", "fmt")
    fmt = fmt if fmt is not _MISSING else None
    auth_data_entry = _get_mapping_entry(value, 2, "2", "authData")
    auth_data_bytes = _coerce_cbor_bytes(auth_data_entry)
    att_stmt_entry = _get_mapping_entry(value, 3, "3", "attStmt")
    if att_stmt_entry is _MISSING:
        att_stmt_entry = None
    att_stmt_bytes = _coerce_cbor_bytes(att_stmt_entry)
    att_stmt_map = att_stmt_entry if isinstance(att_stmt_entry, Mapping) else None
    if not isinstance(fmt, str) or not fmt.strip() or auth_data_bytes is None:
        return None
    if att_stmt_map is None and att_stmt_bytes is None and att_stmt_entry is not None:
        return None

    interpreted: dict[str, Any] = {}
    interpreted["1 (fmt)"] = fmt

    auth_data_details, auth_trailing = ctap_runtime_parse._format_auth_data_for_expanded_json(auth_data_bytes)
    interpreted["2 (authData)"] = auth_data_details
    if auth_trailing:
        trailing_map = ctap_runtime_parse._decode_trailing_map(auth_trailing)
        if trailing_map:
            interpreted["2 (authData trailing)"] = _hex_json_safe(trailing_map)

    if isinstance(att_stmt_map, Mapping):
        att_stmt_details = result_runtime._convert_attestation_statement({"attestationStatement": att_stmt_map})
        sig_value = att_stmt_map.get("sig")
        sig_bytes = _coerce_cbor_bytes(sig_value)
        if sig_bytes is not None:
            att_stmt_details["sig"] = sig_bytes.hex()
        interpreted["3 (attStmt)"] = att_stmt_details
    else:
        if att_stmt_bytes is not None:
            interpreted["3 (attStmt)"] = att_stmt_bytes.hex()
        else:
            interpreted["3 (attStmt)"] = _hex_json_safe(att_stmt_entry)

    optional_labels = {
        4: "epAtt",
        5: "largeBlobKey",
        6: "extensions",
    }
    for key, label in optional_labels.items():
        candidate = _get_mapping_entry(value, key)
        if candidate is _MISSING:
            continue
        interpreted[f"{key} ({label})"] = _convert_optional_ctap_field(candidate)

    extra_keys = [
        key
        for key in value.keys()
        if isinstance(key, int) and key not in {1, 2, 3, 4, 5, 6}
    ]
    for key in sorted(extra_keys):
        interpreted[f"{key}"] = _hex_json_safe(value[key])

    return interpreted


def _interpret_get_assertion_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    if ctap_classify._looks_like_get_assertion_request(value):
        return None
    auth_data_entry = _get_mapping_entry(value, 2, "2", "authData")
    signature_entry = _get_mapping_entry(value, 3, "3", "signature")
    auth_data_bytes = _coerce_cbor_bytes(auth_data_entry)
    signature_bytes = _coerce_cbor_bytes(signature_entry)
    if auth_data_bytes is None:
        return None

    interpreted: dict[str, Any] = {}

    credential_entry = _get_mapping_entry(value, 1, "1", "credential")
    if credential_entry is not _MISSING and credential_entry is not None:
        interpreted["1 (credential)"] = _convert_ctap_credential_descriptor(credential_entry)

    auth_data_details, auth_trailing = ctap_runtime_parse._format_auth_data_for_expanded_json(auth_data_bytes)
    interpreted["2 (authData)"] = auth_data_details

    if signature_bytes is not None:
        interpreted["3 (signature)"] = signature_bytes.hex()
    else:
        interpreted["3 (signature)"] = None

    user_entry = _get_mapping_entry(value, 4, "4", "user")
    if user_entry is not _MISSING and user_entry is not None:
        interpreted["4 (user)"] = ctap_runtime_parse._convert_ctap_user(user_entry)

    optional_labels = {
        5: "numberOfCredentials",
        6: "userSelected",
        7: "largeBlobKey",
        8: "extensions",
    }
    for key, label in optional_labels.items():
        candidate = _get_mapping_entry(value, key)
        if candidate is _MISSING:
            continue
        interpreted[f"{key} ({label})"] = _convert_optional_ctap_field(candidate)

    extra_keys = [
        key
        for key in value.keys()
        if isinstance(key, int) and key not in {1, 2, 3, 4, 5, 6, 7, 8}
    ]
    for key in sorted(extra_keys):
        interpreted[f"{key}"] = _hex_json_safe(value[key])

    if interpreted.get("3 (signature)") is None and auth_trailing:
        trailing_map = ctap_runtime_parse._decode_trailing_map(auth_trailing)
        sig_entry = trailing_map.pop(3, None)
        if sig_entry is not None:
            sig_bytes = _coerce_cbor_bytes(sig_entry)
            if sig_bytes is not None:
                interpreted["3 (signature)"] = sig_bytes.hex()
        user_entry_trailing = trailing_map.pop(4, None)
        if user_entry_trailing is not None:
            interpreted["4 (user)"] = ctap_runtime_parse._convert_ctap_user(user_entry_trailing)
        number_entry = trailing_map.pop(5, None)
        if number_entry is not None:
            interpreted["5 (numberOfCredentials)"] = _convert_optional_ctap_field(number_entry)
        user_selected_entry = trailing_map.pop(6, None)
        if user_selected_entry is not None:
            interpreted["6 (userSelected)"] = _convert_optional_ctap_field(user_selected_entry)
        extensions_entry = trailing_map.pop(8, None)
        if extensions_entry is not None:
            interpreted["8 (extensions)"] = _convert_optional_ctap_field(extensions_entry)
        if trailing_map:
            interpreted["trailingFields"] = _hex_json_safe(trailing_map)

    return interpreted


def _interpret_make_credential_request_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    if not ctap_classify._looks_like_make_credential_request(value):
        return None
    return ctap_classify._build_labeled_ctap_map(
        value,
        ctap_classify._MAKE_CREDENTIAL_REQUEST_LABELS,
        _MAKE_CREDENTIAL_REQUEST_HANDLERS,
    )


def _interpret_get_assertion_request_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    if not ctap_classify._looks_like_get_assertion_request(value):
        return None
    return ctap_classify._build_labeled_ctap_map(
        value,
        ctap_classify._GET_ASSERTION_REQUEST_LABELS,
        _GET_ASSERTION_REQUEST_HANDLERS,
    )
