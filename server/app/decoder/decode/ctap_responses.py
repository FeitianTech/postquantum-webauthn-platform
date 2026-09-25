"""The makeCredential and getAssertion response views of a CTAP map (``ctapDecoded``).

The members are read by their integer keys (CTAP 2.2 section 6.1.2 and 6.2.2);
every other entry is shown too, with its type where it is not an integer, and
``ctap_conformance`` reports such a key.
The conversions they share with the rest of ``ctap`` are looked up there when
called, so a test that patches ``ctap`` patches them here too.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .. import ctap_tables
from . import ctap, response
from .keys import MISSING as _MISSING
from .keys import JsonLabel, json_items, qualified_key_text
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

    converters = {1: lambda fmt: fmt, 2: _auth_data_view, 3: _attestation_statement_view}
    return _member_view(value, ctap_tables.MAKE_CREDENTIAL_RESPONSE, converters)


def _interpret_get_assertion_map(value: Mapping[Any, Any]) -> dict[str, Any] | None:
    if ctap._looks_like_get_assertion_request(value):
        return None
    if _coerce_cbor_bytes(_get_mapping_entry(value, 2)) is None:
        return None

    converters = {1: _credential_view, 2: _auth_data_view, 3: _signature_view, 4: _user_view}
    view = _member_view(value, ctap_tables.GET_ASSERTION_RESPONSE, converters)
    # No signature at all (only a direct call gets here): the member is shown, as null.
    view.setdefault(JsonLabel("3 (signature)"), None)
    return view


def _member_view(
    value: Mapping[Any, Any], members: Mapping[int, str], converters: Mapping[int, Callable[[Any], Any]]
) -> dict[str, Any]:
    """Every entry of ``value``, in the order sent: members labelled, null ones too.

    An integer that is no member is shown by its number. Any other key -- a CTAP
    map numbers its members with integers -- is shown with its type, so that
    neither a reader nor the encoder takes the text "fmt" for member 1.
    """

    def decorate(key: Any, text: str) -> str:
        if isinstance(key, bool) or not isinstance(key, int):
            return qualified_key_text(key)
        label = members.get(key)
        return f"{text} ({label})" if label else text

    view: dict[str, Any] = {}
    for label, key, raw in json_items(value, decorate):
        member = key if isinstance(key, int) and not isinstance(key, bool) else None
        if member in converters:
            view[label] = converters[member](raw)
        elif member in members:
            view[label] = ctap._convert_optional_ctap_field(raw)
        else:
            view[label] = _hex_json_safe(raw)
    return view


def _auth_data_view(raw: Any) -> Any:
    auth_data = _coerce_cbor_bytes(raw)
    if auth_data is None:
        return _hex_json_safe(raw)
    details, _trailing = ctap._format_auth_data_for_expanded_json(auth_data)
    return details


def _attestation_statement_view(raw: Any) -> Any:
    if isinstance(raw, Mapping):
        details = response._convert_attestation_statement({"attestationStatement": raw})
        signature = _coerce_cbor_bytes(raw.get("sig"))
        if signature is not None:
            details["sig"] = signature.hex()
        return details
    statement_bytes = _coerce_cbor_bytes(raw)
    return statement_bytes.hex() if statement_bytes is not None else _hex_json_safe(raw)


def _credential_view(raw: Any) -> Any:
    return None if raw is None else ctap._convert_ctap_credential_descriptor(raw)


def _signature_view(raw: Any) -> Any:
    signature = _coerce_cbor_bytes(raw)
    return signature.hex() if signature is not None else _hex_json_safe(raw)


def _user_view(raw: Any) -> Any:
    return None if raw is None else ctap._convert_ctap_user(raw)
