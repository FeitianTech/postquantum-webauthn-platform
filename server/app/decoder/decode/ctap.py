"""CTAP message classification and interpretation for the decoder."""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from fido2.webauthn import AuthenticatorData

from ...encoding import encode_base64
from ...webauthn.attestation import encode_base64url
from .. import ctap_tables
from . import canonical, cbor_parser, pipeline, response
from .cbor_parser import (
    _CborDecodingError,
    _structure_to_value,
)
from .keys import MISSING, key_identity
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
        descriptor[_format_ctap_entry_key(key, None)] = _hex_json_safe(entry[key])

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
    # Only the integer 1 is member 1: a text "1" or a byte string h'01' is not.
    if isinstance(key, bool) or not isinstance(key, (int, str)):
        return None
    return label_map.get(key)


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
            value = mapping[key]
            if handler is not None:
                result[formatted_key] = handler(value)
            else:
                result[formatted_key] = _hex_json_safe(value)
            seen_keys.add(key_identity(key))
            if label is not None:
                seen_labels.add(label)

    for missing in missing_keys:
        label = _resolve_ctap_label(labels, missing)
        if key_identity(missing) in seen_keys:
            continue
        if label is not None and label in seen_labels:
            continue
        formatted_key = _format_ctap_entry_key(missing, label)
        handler: Callable[[Any], Any] | None = None
        if label is not None and label in handlers:
            handler = handlers[label]
        elif missing in handlers:
            handler = handlers[missing]
        if handler is not None:
            result.setdefault(formatted_key, handler(None))
        else:
            result.setdefault(formatted_key, None)

    return result


def _looks_like_make_credential_request(value: Mapping[Any, Any]) -> bool:
    client_hash_entry = _get_mapping_entry(value, 1, "clientDataHash")
    client_hash_bytes = _coerce_cbor_bytes(client_hash_entry)
    if client_hash_bytes is None:
        return False
    if _extract_mapping_string(value, (1, "fmt")) is not None:
        return False
    if _extract_mapping_bytes(value, (2, "authData")) is not None:
        return False
    rp_entry = _get_mapping_entry(value, 2, "rp")
    user_entry = _get_mapping_entry(value, 3, "user")
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
    fmt_value = _extract_mapping_string(value, (1, "fmt"))
    auth_data_bytes = _extract_mapping_bytes(value, (2, "authData"))
    att_stmt_value = _get_mapping_entry(value, 3, "attStmt")
    if att_stmt_value is MISSING:
        att_stmt_value = None
    att_stmt_bytes = _coerce_cbor_bytes(att_stmt_value)
    att_stmt_map = att_stmt_value if isinstance(att_stmt_value, Mapping) else None
    return fmt_value is not None and auth_data_bytes is not None and (
        att_stmt_map is not None or att_stmt_bytes is not None
    )


def _looks_like_get_assertion_output(value: Mapping[Any, Any]) -> bool:
    auth_data_bytes = _extract_mapping_bytes(value, (2, "authData"))
    signature_bytes = _extract_mapping_bytes(value, (3, "signature"))
    return auth_data_bytes is not None and signature_bytes is not None


def _classify_ctap_response(value: Mapping[Any, Any]) -> str:
    if _looks_like_make_credential_output(value):
        return "make_credential_output"
    if _looks_like_get_assertion_output(value):
        return "get_assertion_output"
    return "other"


def _classify_ctap_map(value: Mapping[Any, Any]) -> str:
    classification = _classify_ctap_response(value)
    if classification != "other":
        return classification
    if _looks_like_make_credential_request(value):
        return "make_credential_input"
    if _looks_like_get_assertion_request(value):
        return "get_assertion_input"
    return "other"


# A command byte says which request its parameters are, whatever their shape.
_REQUEST_KIND_BY_COMMAND = {
    "MAKE_CREDENTIAL": "make_credential_input",
    "GET_ASSERTION": "get_assertion_input",
}


def _classify_ctap_payload(value: Any, prefix: Mapping[str, Any] | None) -> str:
    """Name the CTAP message ``value`` is, reading the byte before it first.

    A command byte decides: its parameters are that command's request. A
    status byte says only that this is a response, not to which command, so
    the response shapes are the only candidates. With no prefix byte, all four
    shapes are.
    """

    if not isinstance(value, Mapping):
        return "other"
    kind = prefix.get("kind") if isinstance(prefix, Mapping) else None
    if kind == "command":
        return _REQUEST_KIND_BY_COMMAND.get(prefix.get("command"), "other")
    if kind == "status":
        return _classify_ctap_response(value)
    return _classify_ctap_map(value)


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
    """Read authenticator data as far as its flags describe it.

    Returns the details, the bytes the flags account for, and any bytes after
    them. The credential public key and the extensions are read with the strict
    parser; one that is not well-formed is shown as hex with a ``parseError``
    saying where, never completed or skipped.
    """

    details: dict[str, Any] = {}
    if len(data) < 37:
        details["parseError"] = "Authenticator data shorter than minimum header."
        return details, data, b""

    rp_id_hash = data[:32]
    flags_byte = data[32]
    sign_count = int.from_bytes(data[33:37], "big")
    offset = 37

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

    if flags_byte & AuthenticatorData.FLAG.AT:
        attested: dict[str, Any] = {}
        details["attestedCredentialData"] = attested
        remaining = len(data) - offset
        if remaining < 18:
            attested["parseError"] = (
                f"Attested credential data truncated: it needs at least 18 bytes, {remaining} remain."
            )
            offset = len(data)
        else:
            aaguid = data[offset : offset + 16]
            declared_len = int.from_bytes(data[offset + 16 : offset + 18], "big")
            offset += 18
            actual_len = min(declared_len, len(data) - offset)
            credential_id = data[offset : offset + actual_len]
            offset += actual_len

            attested["aaguid"] = aaguid.hex()
            attested["credentialIdDeclaredLength"] = declared_len
            attested["credentialIdActualLength"] = actual_len
            attested["credentialId"] = credential_id.hex()
            if actual_len != declared_len:
                attested["lengthMismatch"] = True
                attested["parseError"] = (
                    f"The credential ID declares {declared_len} bytes; {actual_len} remain."
                )
            elif offset < len(data):
                offset = _read_embedded_cbor(data, offset, attested, "credentialPublicKey")

    if flags_byte & AuthenticatorData.FLAG.ED and offset < len(data):
        offset = _read_embedded_cbor(data, offset, details, "extensions")

    return details, data[:offset], data[offset:]


def _read_embedded_cbor(data: bytes, offset: int, target: dict[str, Any], field: str) -> int:
    try:
        node, end, _ = cbor_parser.decode_item(data, offset)
    except _CborDecodingError as exc:
        target[field] = data[offset:].hex()
        target["parseError"] = (
            f"{field} is not well-formed CBOR at authData offset {exc.offset}: {exc.reason}"
        )
        return len(data)
    target[field] = _hex_json_safe(_structure_to_value(node))
    return end


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


def _interpret_ctap_cbor_value(
    value: Any, prefix: Mapping[str, Any] | None = None
) -> dict[str, Any] | None:
    return _interpret_ctap_kind(value, _classify_ctap_payload(value, prefix))


def _interpret_ctap_kind(value: Any, classification: str) -> dict[str, Any] | None:
    interpreter = _CTAP_INTERPRETERS.get(classification)
    if interpreter is None:
        return None
    name, interpret = interpreter
    interpreted = interpret(value)
    if interpreted is None:
        return None
    return {name: interpreted}


def _interpret_make_credential_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    fmt = _get_mapping_entry(value, 1, "fmt")
    fmt = fmt if fmt is not _MISSING else None
    auth_data_entry = _get_mapping_entry(value, 2, "authData")
    auth_data_bytes = _coerce_cbor_bytes(auth_data_entry)
    att_stmt_entry = _get_mapping_entry(value, 3, "attStmt")
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
    auth_data_entry = _get_mapping_entry(value, 2, "authData")
    signature_entry = _get_mapping_entry(value, 3, "signature")
    auth_data_bytes = _coerce_cbor_bytes(auth_data_entry)
    signature_bytes = _coerce_cbor_bytes(signature_entry)
    if auth_data_bytes is None:
        return None

    interpreted: dict[str, Any] = {}

    credential_entry = _get_mapping_entry(value, 1, "credential")
    if credential_entry is not _MISSING and credential_entry is not None:
        interpreted["1 (credential)"] = _convert_ctap_credential_descriptor(credential_entry)

    auth_data_details, _auth_trailing = _format_auth_data_for_expanded_json(auth_data_bytes)
    interpreted["2 (authData)"] = auth_data_details

    if signature_bytes is not None:
        interpreted["3 (signature)"] = signature_bytes.hex()
    else:
        interpreted["3 (signature)"] = None

    user_entry = _get_mapping_entry(value, 4, "user")
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


# What ``ctapDecoded`` calls each kind, and how it reads one. Requests are read
# with the labelled-map builders, which do not second-guess the shape: the
# command byte, or the classification, already said what they are.
_CTAP_INTERPRETERS: dict[str, tuple[str, Callable[[Mapping[Any, Any]], dict[str, Any] | None]]] = {
    "make_credential_output": ("makeCredentialResponse", _interpret_make_credential_map),
    "get_assertion_output": ("getAssertionResponse", _interpret_get_assertion_map),
    "make_credential_input": ("makeCredentialRequest", _build_make_credential_request_expanded_json),
    "get_assertion_input": ("getAssertionRequest", _build_get_assertion_request_expanded_json),
}


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


def _try_decode_cbor(data: bytes, encoding: str, *, lenient: bool = False) -> dict[str, Any] | None:
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

    # One item, parsed strictly unless the caller asked for lenient parsing. A
    # payload that is not well-formed raises with its offset, counted from the
    # first input byte, prefix included.
    start = len(data) - len(payload)
    node, end, skipped = cbor_parser.decode_item(data, start, lenient=lenient)
    base_value = _structure_to_value(node)
    consumed_total = end - start
    remaining = data[end:]

    classification = _classify_ctap_payload(base_value, ctap_details)

    decoded_payload: dict[str, Any] = {}

    expanded_json: dict[str, Any] | None = None
    ctap_decoded: dict[str, Any] | None = None
    hex_decoded_value: Any | None = None

    if isinstance(base_value, Mapping):
        hex_decoded_value = _hex_json_safe(base_value)
        interpreted = _interpret_ctap_kind(base_value, classification)
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
    else:
        hex_decoded_value = _hex_json_safe(base_value)

    if ctap_decoded is not None:
        decoded_payload["ctapDecoded"] = ctap_decoded

    if expanded_json:
        decoded_payload["expandedJson"] = _stringify_mapping_keys(_hex_json_safe(expanded_json))

    if ctap_decoded is None:
        decoded_payload["decodedValue"] = _stringify_mapping_keys(_hex_json_safe(hex_decoded_value))

    findings = canonical.check(node, data) + skipped + _trailing_findings(data, end)

    if ctap_details is not None:
        ctap_details["payloadLength"] = consumed_total
        if remaining and _is_padding_bytes(remaining):
            ctap_details["ignoredPaddingBytes"] = len(remaining)
        elif remaining:
            ctap_details["trailingBytesHex"] = remaining.hex()
        decoded_payload["ctap"] = _stringify_mapping_keys(ctap_details)

    result: dict[str, Any] = {
        "format": "CBOR",
        "inputEncoding": encoding,
        "decoded": decoded_payload,
        "binary": pipeline._binary_summary(data, encoding),
        "decodeMode": "lenient" if lenient else "strict",
    }
    _attach_findings(result, findings)
    return result


def _trailing_findings(data: bytes, end: int) -> list[dict[str, Any]]:
    """Report the bytes after the top-level item: never decoded, never dropped.

    All 0x00 (or 0xff) is what an unstripped HID report ends with, and is
    reported as such -- still reported.
    """

    remaining = data[end:]
    if not remaining:
        return []
    note = " (all 0x00/0xff: HID report padding?)" if _is_padding_bytes(remaining) else ""
    return [
        {
            "code": "trailing-bytes",
            "category": "trailing",
            "offset": end,
            "path": "$",
            "length": len(remaining),
            "hex": remaining.hex(),
            "message": f"Trailing {len(remaining)} byte(s) after CBOR payload{note}.",
        }
    ]


def _attach_findings(result: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    ordered = sorted(findings, key=lambda finding: finding["offset"])
    result["findings"] = ordered
    if ordered:
        result["malformed"] = [finding["message"] for finding in ordered]
