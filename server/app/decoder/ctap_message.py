"""A CTAP message as the decoder shows it, and the bytes that view rebuilds.

A view is ``{message: {label: value}}``, ``message`` one of ``MESSAGES``. Its
members are labelled as CTAP 2.2 section 6 numbers them: ``"1 (fmt)"`` for a
member, the number alone for an integer the message does not define, and any
other key with its type (``ctap_view.key_label``). Every value is spelled by
``ctap_view``, except two shown interpreted in place, each carrying the exact
bytes it was read from, which alone are read back:

- authenticator data, member 2 of both responses: ``raw`` (the bytes its flags
  account for) and ``trailingBytesHex`` (any after them);
- each x5c certificate of a makeCredential response's attestation statement:
  ``raw``.

The framing is ``data.ctap``, beside the view: ``code``, the command or status
byte sent before the message, or null when none was; ``message``, which of them
it is; ``trailingBytesHex``, any bytes after it. ``rebuild`` writes the message
back: the byte, the members in CTAP2 canonical form (``cbor_canonical``), the
trailing bytes. It is what the encoder writes, and what the decoder checks its
own view against (``decode/ctap_self_check.py``).
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from . import ctap_tables, ctap_view
from .cbor_canonical import _canonical_cbor_dumps
from .decode import keys

# Each message's members, by number (CTAP 2.2 section 6).
MESSAGES: dict[str, Mapping[int, str]] = {
    "makeCredentialRequest": ctap_tables.MAKE_CREDENTIAL_PARAMETERS,
    "getAssertionRequest": ctap_tables.GET_ASSERTION_PARAMETERS,
    "makeCredentialResponse": ctap_tables.MAKE_CREDENTIAL_RESPONSE,
    "getAssertionResponse": ctap_tables.GET_ASSERTION_RESPONSE,
    "getInfoResponse": ctap_tables.GET_INFO_RESPONSE,
}
# The members shown interpreted, each with the bytes it holds.
AUTHENTICATOR_DATA = {("makeCredentialResponse", 2), ("getAssertionResponse", 2)}
ATTESTATION_STATEMENT = ("makeCredentialResponse", 3)

_MEMBER_LABEL = re.compile(r"(-?(?:0|[1-9][0-9]*)) \((.+)\)")


def member_label(message: str, key_node: Mapping[str, Any]) -> str:
    """A member's label: ``"N (name)"``, the number alone where the message defines none, a typed key."""

    if key_node.get("majorType") in (0, 1) and "error" not in key_node:
        number = key_node["value"]
        name = MESSAGES[message].get(number)
        return f"{number} ({name})" if name else str(number)
    return ctap_view.key_label(key_node)


def read_member_key(message: str, label: str, path: str = "$") -> Any:
    """The key a member label names; refuses a name that is not the member's, and plain text."""

    match = _MEMBER_LABEL.fullmatch(label)
    if match and keys.typed_key_kind(label) is None:
        number, name = int(match[1]), match[2]
        member = MESSAGES[message].get(number)
        if member != name:
            said = f"is {member}" if member else "is not defined in CTAP 2.2"
            raise ValueError(f'{path}: the label "{label}" names {name}, but member {number} of a {message} {said}.')
        return number
    key = ctap_view.read_key(label, path)
    if isinstance(key, str) and not keys.typed_spelling(label):
        example = f"1 ({MESSAGES[message][1]})"
        raise ValueError(
            f"{path}: {json.dumps(label, ensure_ascii=False)} names no member: a {message} numbers its members, "
            f'as "{example}" or "1"; a text key is written with its type, '
            f"{json.dumps(label, ensure_ascii=False)} (text)."
        )
    return key


def read_members(message: str, view: Mapping[str, Any], path: str = "$") -> dict[Any, Any]:
    """The members a view of ``message`` holds, as the canonical writer takes them."""

    if message not in MESSAGES:
        raise ValueError(f"{path}: {message} is not a CTAP message this view names; it names {', '.join(MESSAGES)}.")
    if not isinstance(view, Mapping):
        raise ValueError(f"{path}.{message} must be an object of members.")
    members: dict[Any, Any] = {}
    for label, value in view.items():
        member_path = f"{path}.{message}{{{json.dumps(label, ensure_ascii=False)}}}"
        key = read_member_key(message, label, member_path)
        if key in members and not isinstance(key, bool):
            raise ValueError(f"{member_path}: member {key} is given twice.")
        members[key] = _read_value(message, key, value, member_path)
    return members


def _read_value(message: str, key: Any, value: Any, path: str) -> Any:
    if (message, key) in AUTHENTICATOR_DATA and isinstance(value, Mapping) and "raw" in value:
        return _hex(value["raw"], f"{path}.raw") + _hex(value.get("trailingBytesHex") or "", f"{path}.trailingBytesHex")
    if (message, key) == ATTESTATION_STATEMENT and isinstance(value, Mapping):
        statement = {}
        for label, entry in value.items():
            entry_path = f"{path}{{{json.dumps(label, ensure_ascii=False)}}}"
            member = ctap_view.read_key(label, entry_path)
            if member == "x5c" and isinstance(entry, list):
                statement[member] = [_certificate(item, f"{entry_path}[{index}]") for index, item in enumerate(entry)]
            else:
                statement[member] = ctap_view.read(entry, entry_path)
        return statement
    return ctap_view.read(value, path)


def _certificate(entry: Any, path: str) -> Any:
    if isinstance(entry, Mapping) and "raw" in entry:
        return _hex(entry["raw"], f"{path}.raw")
    return ctap_view.read(entry, path)


def _hex(value: Any, path: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{path} must be hex.")
    try:
        return bytes.fromhex(value)
    except ValueError:
        raise ValueError(f"{path} must be hex.") from None


def rebuild(message: str, view: Mapping[str, Any], framing: Mapping[str, Any]) -> bytes:
    """The bytes a view and its framing hold: the CTAP byte, the members in canonical form, the trailing bytes."""

    code = framing.get("code")
    if code is not None and (isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 0xFF):
        raise ValueError(f"ctap.code must be a byte (0 to 255), or null for none; it is {json.dumps(code)}.")
    prefix = b"" if code is None else bytes([code])
    trailing = _hex(framing.get("trailingBytesHex") or "", "ctap.trailingBytesHex")
    return prefix + _canonical_cbor_dumps(read_members(message, view, "ctapDecoded")) + trailing
