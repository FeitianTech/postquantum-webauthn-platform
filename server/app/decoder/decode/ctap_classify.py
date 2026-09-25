"""Which CTAP message a decoded map is: by the command or status byte before it, else by its shape.

A command byte says which request its parameters are. A status byte says only
that this is a response. With no byte, the map's shape is all there is: the
member types CTAP 2.2 section 6 gives each message.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from . import get_info
from .ambiguous_input import finding
from .keys import MISSING
from .keys import coerce_cbor_bytes as _coerce_cbor_bytes
from .keys import get_mapping_entry as _get_mapping_entry


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


# The shapes read integer members only: CTAP 2.2 section 6 numbers them, and a
# text "fmt" or "rpId" is some other map's key (a WebAuthn attestation object's).


def _looks_like_make_credential_request(value: Mapping[Any, Any]) -> bool:
    # clientDataHash (1) is bytes; rp (2) is a map, where a response has authData bytes.
    if _extract_mapping_bytes(value, (1,)) is None or _extract_mapping_bytes(value, (2,)) is not None:
        return False
    return _get_mapping_entry(value, 2) is not MISSING and _get_mapping_entry(value, 3) is not MISSING


def _looks_like_get_assertion_request(value: Mapping[Any, Any]) -> bool:
    # rpId (1) and clientDataHash (2); a byte-string 3 is a response's signature.
    if _extract_mapping_string(value, (1,)) is None or _extract_mapping_bytes(value, (2,)) is None:
        return False
    return _extract_mapping_bytes(value, (3,)) is None


def _looks_like_make_credential_output(value: Mapping[Any, Any]) -> bool:
    fmt_value = _extract_mapping_string(value, (1,))
    auth_data_bytes = _extract_mapping_bytes(value, (2,))
    att_stmt_value = _get_mapping_entry(value, 3)
    if att_stmt_value is MISSING:
        att_stmt_value = None
    att_stmt_bytes = _coerce_cbor_bytes(att_stmt_value)
    att_stmt_map = att_stmt_value if isinstance(att_stmt_value, Mapping) else None
    compound = fmt_value == "compound" and isinstance(att_stmt_value, list)
    return fmt_value is not None and auth_data_bytes is not None and (
        att_stmt_map is not None or att_stmt_bytes is not None or compound
    )


def _looks_like_get_assertion_output(value: Mapping[Any, Any]) -> bool:
    auth_data_bytes = _extract_mapping_bytes(value, (2,))
    signature_bytes = _extract_mapping_bytes(value, (3,))
    return auth_data_bytes is not None and signature_bytes is not None


def _classify_ctap_response(value: Mapping[Any, Any]) -> str:
    if _looks_like_make_credential_output(value):
        return "make_credential_output"
    if _looks_like_get_assertion_output(value):
        return "get_assertion_output"
    if get_info.looks_like_get_info(value):
        return "get_info_output"
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


# What each shape is called in a finding.
SHAPE_NAMES = {
    "make_credential_output": "a makeCredential response",
    "get_assertion_output": "a getAssertion response",
    "get_info_output": "a getInfo response",
    "make_credential_input": "a makeCredential request",
    "get_assertion_input": "a getAssertion request",
}
_RESPONSE_SHAPES = {
    "make_credential_output": _looks_like_make_credential_output,
    "get_assertion_output": _looks_like_get_assertion_output,
    "get_info_output": get_info.looks_like_get_info,
}
_REQUEST_SHAPES = {
    "make_credential_input": _looks_like_make_credential_request,
    "get_assertion_input": _looks_like_get_assertion_request,
}
PLAIN_MAP = "a CBOR map that is no CTAP message"


def shape_findings(value: Any, prefix: Mapping[str, Any] | None, classification: str) -> list[dict[str, Any]]:
    """An ``ambiguous-input`` finding for each other CTAP message ``value``'s shape is.

    A command byte decides, so there is none after one. After a status byte the
    response shapes are the candidates; with no byte, every shape is, and so is
    the plain map the item also is.
    """

    kind = prefix.get("kind") if isinstance(prefix, Mapping) else None
    if kind == "command" or not isinstance(value, Mapping):
        return []
    shapes = dict(_RESPONSE_SHAPES) if kind == "status" else {**_RESPONSE_SHAPES, **_REQUEST_SHAPES}
    matching = [name for name, looks_like in shapes.items() if looks_like(value)]
    taken = SHAPE_NAMES.get(classification, PLAIN_MAP)
    others = [SHAPE_NAMES[name] for name in matching if name != classification]
    if kind is None and classification != "other":
        taken += " with no CTAP command or status byte"
        others.append(PLAIN_MAP)
    return [finding(taken, other) for other in others]
