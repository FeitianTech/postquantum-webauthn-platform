"""CTAP message classification and interpretation for the decoder."""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from io import BytesIO
from typing import Any

import cbor2

from fido2 import cbor
from fido2.webauthn import AuthenticatorData

from ...encoding import encode_base64
from ...webauthn.attestation import encode_base64url, make_json_safe
from .. import ctap_tables
from . import cbor_parser, pipeline, response
from .cbor_parser import (
    _CborDecodingError,
    _decode_cbor_sequence_impl,
    _structure_to_value,
)
from .keys import MISSING
from .keys import MISSING as _MISSING
from .keys import coerce_cbor_bytes as _coerce_cbor_bytes
from .keys import get_mapping_entry as _get_mapping_entry
from .keys import hex_json_safe as _hex_json_safe
from .keys import stringify_mapping_keys as _stringify_mapping_keys


def _extract_mapping_string(value: Mapping[Any, Any], keys: Iterable[Any]) -> str | None:
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


def _extract_mapping_bytes(value: Mapping[Any, Any], keys: Iterable[Any]) -> bytes | None:
    if not isinstance(value, Mapping):
        return None
    candidate = _get_mapping_entry(value, *keys)
    if candidate is MISSING:
        return None
    candidate_bytes = _coerce_cbor_bytes(candidate)
    if candidate_bytes is not None:
        return candidate_bytes
    return None


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

    descriptor: dict[str, Any] = {}
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


def _labels(members: Mapping[int, str]) -> dict[Any, str]:
    """Look a CTAP member up by its number or by its name; input maps use either."""

    labels: dict[Any, str] = dict(members)
    labels.update((name, name) for name in members.values())
    return labels


_MAKE_CREDENTIAL_REQUEST_LABELS = _labels(ctap_tables.MAKE_CREDENTIAL_PARAMETERS)
_GET_ASSERTION_REQUEST_LABELS = _labels(ctap_tables.GET_ASSERTION_PARAMETERS)
_MAKE_CREDENTIAL_RESPONSE_LABELS = _labels(ctap_tables.MAKE_CREDENTIAL_RESPONSE)
_GET_ASSERTION_RESPONSE_LABELS = _labels(ctap_tables.GET_ASSERTION_RESPONSE)


def _resolve_ctap_label(label_map: Mapping[Any, str], key: Any) -> str | None:
    if key in label_map:
        return label_map[key]
    key_str = str(key)
    if key_str in label_map:
        return label_map[key_str]
    return None


def _format_ctap_entry_key(key: Any, label: str | None) -> str:
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
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    seen_keys: set = set()
    seen_labels: set = set()

    if isinstance(mapping, Mapping):
        for key in mapping:
            label = _resolve_ctap_label(labels, key)
            formatted_key = _format_ctap_entry_key(key, label)
            handler: Callable[[Any], Any] | None = None
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
        handler: Callable[[Any], Any] | None = None
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


def _summarize_bytes_for_json(data: bytes) -> dict[str, Any]:
    return {
        "length": len(data),
        "hex": data.hex(),
        "base64": encode_base64(data),
        "base64url": encode_base64url(data),
    }


def _parse_authenticator_data_bytes(data: bytes) -> tuple[dict[str, Any], bytes, bytes]:
    details: dict[str, Any] = {}
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

    def _decode_cbor_item(buffer: bytes) -> tuple[Any, int]:
        value, consumed = cbor_parser._lenient_decode_from(buffer, 0)
        return value, consumed

    at_flag = bool(flags_byte & AuthenticatorData.FLAG.AT)
    ed_flag = bool(flags_byte & AuthenticatorData.FLAG.ED)

    attested_trailing = b""
    if at_flag:
        attested: dict[str, Any] = {}
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


def _format_auth_data_for_expanded_json(auth_data_bytes: bytes) -> tuple[dict[str, Any], bytes]:
    details, trimmed, trailing = _parse_authenticator_data_bytes(auth_data_bytes)
    formatted: dict[str, Any] = dict(details)
    formatted.setdefault("raw", trimmed.hex())
    if trailing:
        formatted["trailingBytesHex"] = trailing.hex()
    return formatted, trailing


def _format_att_stmt_for_expanded_json(att_stmt: Any) -> dict[str, Any]:
    formatted: dict[str, Any] = {}

    if isinstance(att_stmt, Mapping):
        for key, value in att_stmt.items():
            if key == "sig":
                sig_bytes = _coerce_cbor_bytes(value)
                if sig_bytes is not None:
                    formatted["sig"] = sig_bytes.hex()
                else:
                    formatted["sig"] = _hex_json_safe(value)
            elif key == "x5c":
                formatted["x5c"] = response._convert_certificate_chain(value)
            else:
                formatted[key] = _hex_json_safe(value)
        return formatted

    sig_bytes = _coerce_cbor_bytes(att_stmt)
    if sig_bytes is not None:
        formatted["sig"] = sig_bytes.hex()
    elif att_stmt is not None:
        formatted["value"] = _hex_json_safe(att_stmt)

    return formatted


def _convert_user_text_value(value: Any) -> Any:
    if isinstance(value, str):
        return value

    data_bytes = _coerce_cbor_bytes(value)
    if data_bytes is None:
        return _hex_json_safe(value)

    text_value = pipeline._try_decode_utf8(data_bytes)
    binary_summary = pipeline._binary_summary(
        data_bytes, "utf-8" if text_value is not None else "binary"
    )
    if text_value is None:
        return binary_summary

    return {"text": text_value, "binary": binary_summary}


def _convert_ctap_user(entry: Any) -> Any:
    # A CTAP user entity is a map. Anything else is shown as it was sent: a
    # byte string or text is never re-read as CBOR, base64 or hex to make one.
    data_bytes = _coerce_cbor_bytes(entry)
    if data_bytes is not None:
        return data_bytes.hex()

    if not isinstance(entry, Mapping):
        return _hex_json_safe(entry)

    user: dict[str, Any] = {}
    id_value = _get_mapping_entry(entry, "id", 1)
    if id_value is not _MISSING:
        id_bytes = _coerce_cbor_bytes(id_value)
        if id_bytes is not None:
            user["id"] = id_bytes.hex()

    name_value = _get_mapping_entry(entry, "name", 2)
    if name_value is not _MISSING:
        user["name"] = _convert_user_text_value(name_value)

    display_name_value = _get_mapping_entry(entry, "displayName", 3)
    if display_name_value is not _MISSING:
        user["displayName"] = _convert_user_text_value(display_name_value)

    icon_value = _get_mapping_entry(entry, "icon", 4)
    if icon_value is not _MISSING:
        user["icon"] = _convert_user_text_value(icon_value)

    for key in entry:
        if key in {"id", "name", "displayName", "icon"} or key in {1, 2, 3, 4}:
            continue
        user[_format_ctap_entry_key(key, None)] = _hex_json_safe(entry[key])

    return user


# The converter tables the labelled-map builder dispatches through.
#
# Two spellings appear below and the difference is load-bearing. An entry that
# names a function directly captures that object when this module is imported,
# so a test patching the name later is NOT seen here. An entry wrapped in a
# lambda resolves the global on every call, so a patch IS seen. These fragments
# used to live in separate modules and the lambdas also worked around a cycle
# between them; the cycle is gone now that they share a module, but the
# patch-visibility difference remains. Do not "simplify" a lambda into a bare
# reference -- that silently changes what a test exercises.
_MAKE_CREDENTIAL_REQUEST_HANDLERS: dict[Any, Callable[[Any], Any]] = {
    "clientDataHash": _convert_optional_ctap_field,
    "rp": _hex_json_safe,
    "user": lambda value: _convert_ctap_user_field(value),
    "pubKeyCredParams": lambda value: _convert_pub_key_cred_params(value),
    "excludeList": lambda value: _convert_ctap_allow_list(value),
    "extensions": _hex_json_safe,
    "options": _hex_json_safe,
    "pinUvAuthParam": _convert_optional_ctap_field,
    "pinUvAuthProtocol": _hex_json_safe,
    "enterpriseAttestation": _hex_json_safe,
    "attestationFormatsPreference": _hex_json_safe,
}

_GET_ASSERTION_REQUEST_HANDLERS: dict[Any, Callable[[Any], Any]] = {
    "rpId": _hex_json_safe,
    "clientDataHash": _convert_optional_ctap_field,
    "allowList": lambda value: _convert_ctap_allow_list(value),
    "extensions": _hex_json_safe,
    "options": _hex_json_safe,
    "pinUvAuthParam": _convert_optional_ctap_field,
    "pinUvAuthProtocol": _hex_json_safe,
}

_MAKE_CREDENTIAL_RESPONSE_HANDLERS: dict[Any, Callable[[Any], Any]] = {
    "fmt": _hex_json_safe,
    "authData": lambda value: _convert_auth_data_field(value),
    "attStmt": lambda value: _convert_att_stmt_field(value),
    "epAtt": _convert_optional_ctap_field,
    "largeBlobKey": _convert_optional_ctap_field,
    "unsignedExtensionOutputs": _convert_optional_ctap_field,
}

_GET_ASSERTION_RESPONSE_HANDLERS: dict[Any, Callable[[Any], Any]] = {
    "credential": _convert_ctap_credential_descriptor,
    "authData": lambda value: _convert_auth_data_field(value),
    "signature": lambda value: _convert_signature_field(value),
    "user": lambda value: _convert_ctap_user_field(value),
    "numberOfCredentials": _convert_optional_ctap_field,
    "userSelected": _convert_optional_ctap_field,
    "largeBlobKey": _convert_optional_ctap_field,
    "unsignedExtensionOutputs": _convert_optional_ctap_field,
}


def _build_make_credential_request_expanded_json(
    value: Mapping[Any, Any]
) -> dict[str, Any]:
    return _build_labeled_ctap_map(
        value,
        _MAKE_CREDENTIAL_REQUEST_LABELS,
        _MAKE_CREDENTIAL_REQUEST_HANDLERS,
    )


def _build_get_assertion_request_expanded_json(
    value: Mapping[Any, Any]
) -> dict[str, Any]:
    return _build_labeled_ctap_map(
        value,
        _GET_ASSERTION_REQUEST_LABELS,
        _GET_ASSERTION_REQUEST_HANDLERS,
    )


def _build_make_credential_expanded_json(value: Mapping[Any, Any]) -> dict[str, Any]:
    return _build_labeled_ctap_map(
        value,
        _MAKE_CREDENTIAL_RESPONSE_LABELS,
        _MAKE_CREDENTIAL_RESPONSE_HANDLERS,
    )


def _build_get_assertion_expanded_json(value: Mapping[Any, Any]) -> dict[str, Any]:
    return _build_labeled_ctap_map(
        value,
        _GET_ASSERTION_RESPONSE_LABELS,
        _GET_ASSERTION_RESPONSE_HANDLERS,
        missing_keys=(3,),
    )


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

    auth_data_details, _auth_trailing = _format_auth_data_for_expanded_json(auth_data_bytes)
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
        interpreted[f"{key} ({label})"] = _convert_optional_ctap_field(candidate)

    extra_keys = [
        key
        for key in value.keys()
        if isinstance(key, int) and key not in members
    ]
    for key in sorted(extra_keys):
        interpreted[f"{key}"] = _hex_json_safe(value[key])

    return interpreted


def _interpret_get_assertion_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    if _looks_like_get_assertion_request(value):
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

    auth_data_details, _auth_trailing = _format_auth_data_for_expanded_json(auth_data_bytes)
    interpreted["2 (authData)"] = auth_data_details

    if signature_bytes is not None:
        interpreted["3 (signature)"] = signature_bytes.hex()
    else:
        interpreted["3 (signature)"] = None

    user_entry = _get_mapping_entry(value, 4, "4", "user")
    if user_entry is not _MISSING and user_entry is not None:
        interpreted["4 (user)"] = _convert_ctap_user(user_entry)

    members = ctap_tables.GET_ASSERTION_RESPONSE
    for key, label in members.items():
        if key <= 4:
            continue
        candidate = _get_mapping_entry(value, key)
        if candidate is _MISSING:
            continue
        interpreted[f"{key} ({label})"] = _convert_optional_ctap_field(candidate)

    extra_keys = [
        key
        for key in value.keys()
        if isinstance(key, int) and key not in members
    ]
    for key in sorted(extra_keys):
        interpreted[f"{key}"] = _hex_json_safe(value[key])

    return interpreted


def _interpret_make_credential_request_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    if not _looks_like_make_credential_request(value):
        return None
    return _build_labeled_ctap_map(
        value,
        _MAKE_CREDENTIAL_REQUEST_LABELS,
        _MAKE_CREDENTIAL_REQUEST_HANDLERS,
    )


def _interpret_get_assertion_request_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    if not _looks_like_get_assertion_request(value):
        return None
    return _build_labeled_ctap_map(
        value,
        _GET_ASSERTION_REQUEST_LABELS,
        _GET_ASSERTION_REQUEST_HANDLERS,
    )


def _extract_ctap_prefix(data: bytes) -> tuple[dict[str, Any] | None, bytes]:
    """Read the CTAP command or status byte ``data`` starts with.

    A request is a command byte and its CBOR parameters; a response is a status
    byte, followed by CBOR only on success. So a byte with a payload after it is
    a command, or SUCCESS; a byte on its own is an error status or a command sent
    without parameters. Where a lone byte names both (0x04 is GET_INFO and
    INVALID_SEQ), both readings are given rather than one picked.
    """

    if not data:
        return None, data
    code, payload = data[0], data[1:]
    command = ctap_tables.COMMANDS.get(code)
    status = ctap_tables.STATUSES.get(code)

    if code == ctap_tables.SUCCESS:
        command = None
    elif payload:
        status = None

    if command is None and status is None:
        return None, data

    prefix: dict[str, Any] = {"code": code, "codeHex": f"0x{code:02x}"}
    readings: list[str] = []
    if command is not None:
        prefix["command"] = command
        readings.append(f"{command} command")
    if status is not None:
        prefix["status"] = status
        readings.append(f"{status} status")
    prefix["kind"] = " or ".join(kind for kind, name in (("command", command), ("status", status)) if name)
    prefix["meaning"] = " or ".join(readings)
    return prefix, payload


def _is_padding_bytes(data: bytes) -> bool:
    if not data:
        return True
    return all(byte in (0x00, 0xFF) for byte in data)


def _json_safe_with_stringified_keys(value: Any) -> Any:
    return _stringify_mapping_keys(make_json_safe(value))


def _decode_cbor_sequence(payload: bytes) -> tuple[list[dict[str, Any]], list[Any], int, bytes]:
    def _cbor2_decode_with_consumed(data: bytes) -> tuple[Any, int]:
        fp = BytesIO(data)
        decoder = cbor2.CBORDecoder(fp)
        return decoder.decode(), fp.tell()

    return _decode_cbor_sequence_impl(
        payload,
        cbor_decode_from=cbor.decode_from,
        cbor_decoder_factory=_cbor2_decode_with_consumed,
        decode_cbor_structure=cbor_parser._decode_cbor_structure,
        structure_to_value=_structure_to_value,
        lenient_decode_from=lambda data, offset=0: cbor_parser._lenient_decode_from(data, offset),
        json_safe_with_stringified_keys=_json_safe_with_stringified_keys,
        cbor_error_type=_CborDecodingError,
    )


def _try_decode_cbor(data: bytes, encoding: str) -> dict[str, Any] | None:
    if not data:
        return None

    ctap_info, payload = _extract_ctap_prefix(data)
    ctap_details = dict(ctap_info) if ctap_info is not None else None

    if not payload:
        decoded_payload: dict[str, Any] = {
            "decodedValue": {"summary": "Empty CBOR payload", "byteLength": 0},
        }
        if ctap_details is not None:
            ctap_details["payloadLength"] = 0
            decoded_payload["ctap"] = _stringify_mapping_keys(ctap_details)
        return {
            "format": "CBOR",
            "inputEncoding": encoding,
            "decoded": decoded_payload,
            "binary": pipeline._binary_summary(data, encoding),
        }

    structures, values, consumed_total, remaining = _decode_cbor_sequence(payload)
    if not structures:
        return None

    base_value = values[0]
    extra_values = values[1:]

    classification = _classify_ctap_map(base_value) if isinstance(base_value, Mapping) else "other"

    decoded_payload: dict[str, Any] = {}

    expanded_json: dict[str, Any] | None = None
    ctap_decoded: dict[str, Any] | None = None
    hex_decoded_value: Any | None = None

    if isinstance(base_value, Mapping):
        hex_decoded_value = _hex_json_safe(base_value)
        interpreted = _interpret_ctap_cbor_value(base_value)
        if interpreted is not None:
            ctap_decoded = _stringify_mapping_keys(_hex_json_safe(interpreted))

        if classification == "make_credential_output":
            expanded_json = _build_make_credential_expanded_json(base_value)
        elif classification == "get_assertion_output":
            expanded_json = _build_get_assertion_expanded_json(base_value)
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

    warnings: list[str] = []

    if ctap_details is not None:
        ctap_details["payloadLength"] = consumed_total

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

    result: dict[str, Any] = {
        "format": "CBOR",
        "inputEncoding": encoding,
        "decoded": decoded_payload,
        "binary": pipeline._binary_summary(data, encoding),
    }
    if warnings:
        result["malformed"] = warnings
    return result
