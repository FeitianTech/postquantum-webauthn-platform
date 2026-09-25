"""CTAP messages in the decoder: the command or status byte, the views of each message, the payload read."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .. import ctap_tables
from . import (
    canonical,
    cbor_parser,
    get_info,
    interpretations,
    key_collisions,
    pipeline,
    response,
)
from .cbor_parser import _structure_to_value
from .ctap_auth_data import _format_auth_data_for_expanded_json
from .ctap_classify import (
    _classify_ctap_payload,
    _looks_like_get_assertion_request,
    _looks_like_make_credential_request,
)
from .ctap_prefix import _extract_ctap_prefix, _is_padding_bytes, prefix_not_read
from .ctap_responses import _interpret_get_assertion_map, _interpret_make_credential_map
from .findings import _attach_findings, _trailing_findings
from .keys import JsonLabel, json_items, key_identity, qualified_key_text
from .keys import coerce_cbor_bytes as _coerce_cbor_bytes
from .keys import hex_json_safe as _hex_json_safe
from .keys import stringify_mapping_keys as _stringify_mapping_keys


def _convert_optional_ctap_field(value: Any) -> Any:
    data_bytes = _coerce_cbor_bytes(value)
    if data_bytes is not None:
        return data_bytes.hex()
    return _hex_json_safe(value)


def _convert_ctap_credential_descriptor(entry: Any) -> Any:
    # A PublicKeyCredentialDescriptor names its members with text keys (WebAuthn
    # L3 section 5.8.3): the integer 1 is not "id". Shown as sent, every member.
    return _hex_json_safe(entry)


# CTAP numbers members with integer keys; these name them by number only.
_MAKE_CREDENTIAL_REQUEST_LABELS = ctap_tables.MAKE_CREDENTIAL_PARAMETERS
_GET_ASSERTION_REQUEST_LABELS = ctap_tables.GET_ASSERTION_PARAMETERS
_MAKE_CREDENTIAL_RESPONSE_LABELS = ctap_tables.MAKE_CREDENTIAL_RESPONSE
_GET_ASSERTION_RESPONSE_LABELS = ctap_tables.GET_ASSERTION_RESPONSE


def _resolve_ctap_label(label_map: Mapping[Any, str], key: Any) -> str | None:
    # Only the integer 1 is member 1: not a text "1", a byte string h'01', nor
    # the text "clientDataHash" -- a name is not a member key in CTAP.
    if isinstance(key, bool) or not isinstance(key, int):
        return None
    return label_map.get(key)


def _format_ctap_entry_key(key: Any, label: str | None) -> str:
    if isinstance(key, (bytes, bytearray)):
        key_display = bytes(key).hex()
    else:
        key_display = str(key)
    return JsonLabel(f"{key_display} ({label})" if label else key_display)


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
        def labelled(key: Any, text: str) -> str:
            # CTAP numbers members with integers: any other key is shown with its
            # type, so that the text "rp" is never read back as member 2.
            if isinstance(key, bool) or not isinstance(key, int):
                return qualified_key_text(key)
            label = _resolve_ctap_label(labels, key)
            return f"{text} ({label})" if label else text

        for formatted_key, key, value in json_items(mapping, labelled):
            label = _resolve_ctap_label(labels, key)
            handler = handlers.get(label) if label is not None else None
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
        handler = handlers.get(label) if label is not None else None
        if handler is not None:
            result.setdefault(formatted_key, handler(None))
        else:
            result.setdefault(formatted_key, None)

    return result


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
        auth_info, _trailing = _format_auth_data_for_expanded_json(auth_bytes)
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


_USER_TEXT_MEMBERS = ("name", "displayName", "icon")


def _convert_ctap_user(entry: Any) -> Any:
    # A CTAP user entity is a map. Anything else is shown as it was sent: a
    # byte string or text is never re-read as CBOR, base64 or hex to make one.
    if not isinstance(entry, Mapping):
        return _hex_json_safe(entry)
    # PublicKeyCredentialUserEntity names its members with text keys (WebAuthn L3
    # section 5.4.3): the integer 2 is not "name". Every member is shown.
    return {
        label: _convert_user_text_value(value) if key in _USER_TEXT_MEMBERS else _hex_json_safe(value)
        for label, key, value in json_items(entry)
    }


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
    "get_info_output": ("getInfoResponse", get_info.interpret_get_info),
    "make_credential_input": ("makeCredentialRequest", _build_make_credential_request_expanded_json),
    "get_assertion_input": ("getAssertionRequest", _build_get_assertion_request_expanded_json),
}


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

    extra, located = interpretations.for_ctap(classification, base_value, node, data)
    findings = canonical.check(node, data) + key_collisions.check(node) + skipped + _trailing_findings(data, end) + located + prefix_not_read(data)

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
        "extraData": extra,
    }
    _attach_findings(result, findings)
    return result
