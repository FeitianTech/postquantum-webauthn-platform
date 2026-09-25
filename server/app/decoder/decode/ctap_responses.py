"""The makeCredential and getAssertion response views of a CTAP map (``ctapDecoded``).

The members are read by their integer keys (CTAP 2.2 section 6.1.2 and 6.2.2).
The conversions they share with the rest of ``ctap`` are looked up there when
called, so a test that patches ``ctap`` patches them here too.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .. import ctap_tables
from . import ctap, response
from .keys import MISSING as _MISSING
from .keys import JsonLabel
from .keys import coerce_cbor_bytes as _coerce_cbor_bytes
from .keys import get_mapping_entry as _get_mapping_entry
from .keys import hex_json_safe as _hex_json_safe


def _interpret_make_credential_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    fmt = _get_mapping_entry(value, 1)
    fmt = fmt if fmt is not _MISSING else None
    auth_data_entry = _get_mapping_entry(value, 2)
    auth_data_bytes = _coerce_cbor_bytes(auth_data_entry)
    att_stmt_entry = _get_mapping_entry(value, 3)
    if att_stmt_entry is _MISSING:
        att_stmt_entry = None
    att_stmt_bytes = _coerce_cbor_bytes(att_stmt_entry)
    att_stmt_map = att_stmt_entry if isinstance(att_stmt_entry, Mapping) else None
    if not isinstance(fmt, str) or not fmt.strip() or auth_data_bytes is None:
        return None
    compound = fmt == "compound" and isinstance(att_stmt_entry, list)
    if att_stmt_map is None and att_stmt_bytes is None and att_stmt_entry is not None and not compound:
        return None

    interpreted: dict[str, Any] = {}
    interpreted["1 (fmt)"] = fmt

    auth_data_details, _auth_trailing = ctap._format_auth_data_for_expanded_json(auth_data_bytes)
    interpreted["2 (authData)"] = auth_data_details

    if isinstance(att_stmt_map, Mapping):
        att_stmt_details = response._convert_attestation_statement({"attestationStatement": att_stmt_map})
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

    members = ctap_tables.MAKE_CREDENTIAL_RESPONSE
    for key, label in members.items():
        if key <= 3:
            continue
        candidate = _get_mapping_entry(value, key)
        if candidate is _MISSING:
            continue
        interpreted[f"{key} ({label})"] = ctap._convert_optional_ctap_field(candidate)

    extra_keys = [
        key
        for key in value.keys()
        if isinstance(key, int) and key not in members
    ]
    for key in sorted(extra_keys):
        interpreted[f"{key}"] = _hex_json_safe(value[key])

    return _labelled(interpreted)


def _interpret_get_assertion_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    if ctap._looks_like_get_assertion_request(value):
        return None
    auth_data_entry = _get_mapping_entry(value, 2)
    signature_entry = _get_mapping_entry(value, 3)
    auth_data_bytes = _coerce_cbor_bytes(auth_data_entry)
    signature_bytes = _coerce_cbor_bytes(signature_entry)
    if auth_data_bytes is None:
        return None

    interpreted: dict[str, Any] = {}

    credential_entry = _get_mapping_entry(value, 1)
    if credential_entry is not _MISSING and credential_entry is not None:
        interpreted["1 (credential)"] = ctap._convert_ctap_credential_descriptor(credential_entry)

    auth_data_details, _auth_trailing = ctap._format_auth_data_for_expanded_json(auth_data_bytes)
    interpreted["2 (authData)"] = auth_data_details

    if signature_bytes is not None:
        interpreted["3 (signature)"] = signature_bytes.hex()
    else:
        interpreted["3 (signature)"] = None

    user_entry = _get_mapping_entry(value, 4)
    if user_entry is not _MISSING and user_entry is not None:
        interpreted["4 (user)"] = ctap._convert_ctap_user(user_entry)

    members = ctap_tables.GET_ASSERTION_RESPONSE
    for key, label in members.items():
        if key <= 4:
            continue
        candidate = _get_mapping_entry(value, key)
        if candidate is _MISSING:
            continue
        interpreted[f"{key} ({label})"] = ctap._convert_optional_ctap_field(candidate)

    extra_keys = [
        key
        for key in value.keys()
        if isinstance(key, int) and key not in members
    ]
    for key in sorted(extra_keys):
        interpreted[f"{key}"] = _hex_json_safe(value[key])

    return _labelled(interpreted)


def _labelled(interpreted: dict[str, Any]) -> dict[str, Any]:
    # The member labels ("1 (fmt)") are spelled here, not keys of the input:
    # later passes over the view keep them as they are.
    return {JsonLabel(label): value for label, value in interpreted.items()}
