"""A number a client sent where fido2 reads bytes, found before fido2 reads it.

fido2 2.2.1 reads a member it declares as bytes by wrapping any value that is not text in
the type itself (``utils._DataClassMapping._parse_value``), and ``websafe_decode`` wraps
one in ``bytes``: an integer N becomes N zero bytes, so nine digits ask for 50 MB.
``number_refusal`` follows the types fido2 declares for the class the app is about to hand
a client's JSON (optional, lists, mappings, nested classes), the way fido2 follows them,
and inside the bytes fido2 parses further: the client data's challenge, the attestation
object's ``authData``, and an android-safetynet statement's nonce and certificates, which
the attestation checks have fido2 read. Each is decoded once more here, as fido2 decodes it.

A boolean is an integer to Python, but ``bytes(True)`` is one byte: it is left to fido2.
"""
from __future__ import annotations

import dataclasses
import json
import types
import typing
from collections.abc import Mapping, Sequence
from typing import Any

from fido2 import cbor
from fido2.utils import websafe_decode
from fido2.webauthn import AttestationObject, CollectedClientData

_TEXT = "text"
_BYTE_STRING = "a byte string"


def number_refusal(cls: type, value: Any) -> str | None:
    """The sentence refusing ``value`` when it holds a number where ``cls`` reads bytes, else None."""

    found = _in_fields(cls, value, "")
    return None if found is None else f"{found[0]} must be {found[1]}, not a number."


def client_data_number(data: bytes | None) -> bool:
    """Whether client data's JSON holds a number as its challenge, which ``CollectedClientData`` makes bytes."""

    client_data = _json(data)
    return isinstance(client_data, dict) and _is_number(client_data.get("challenge"))


def _is_number(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _in_fields(cls: type, value: Any, path: str) -> tuple[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    hints = typing.get_type_hints(cls)
    for field in dataclasses.fields(cls):
        key = cls._get_field_key(field)
        found = _in_value(hints[field.name], value.get(key), f"{path}{key}")
        if found is not None:
            return found
    return None


def _in_value(declared: Any, value: Any, path: str) -> tuple[str, str] | None:
    if value is None:
        return None
    origin = typing.get_origin(declared)
    if origin in (typing.Union, types.UnionType):  # fido2's optional members, ``X | None``
        declared = typing.get_args(declared)[0]
        origin = typing.get_origin(declared)
    if isinstance(declared, type) and issubclass(declared, bytes):
        return (path, _TEXT) if _is_number(value) else _inside(declared, value, path)
    if dataclasses.is_dataclass(declared) and hasattr(declared, "from_dict"):
        return _in_fields(declared, value, f"{path}.")
    if origin is not None and issubclass(origin, Mapping) and isinstance(value, Mapping):
        item_type = typing.get_args(declared)[1]
        items = [(f"{path}.{key}", item) for key, item in value.items()]
    elif origin is not None and issubclass(origin, Sequence) and isinstance(value, list):
        item_type = typing.get_args(declared)[0]
        items = [(f"{path}[{index}]", item) for index, item in enumerate(value)]
    else:
        return None
    for item_path, item in items:
        found = _in_value(item_type, item, item_path)
        if found is not None:
            return found
    return None


def _as_fido2_reads(value: Any) -> bytes | None:
    """``value`` as fido2 makes bytes of text (lenient base64url) or a list of byte values; None when it cannot."""

    try:
        if isinstance(value, (str, bytes)):
            return websafe_decode(value)
        return bytes(value) if isinstance(value, list) else None
    except (TypeError, ValueError):
        return None


def _json(data: bytes | None) -> Any:
    try:
        return json.loads(data.decode()) if data is not None else None
    except (ValueError, RecursionError):
        return None


def _inside(declared: type, value: Any, path: str) -> tuple[str, str] | None:
    """A number inside the bytes of a member fido2 parses further."""

    if declared is CollectedClientData and client_data_number(_as_fido2_reads(value)):
        return f"{path}'s challenge", _TEXT
    if declared is AttestationObject and (data := _as_fido2_reads(value)) is not None:
        try:
            attestation = cbor.decode(data)
        except Exception:  # fido2's decoder raises what the bytes make it raise; fido2 refuses them after
            return None
        if not isinstance(attestation, Mapping):
            return None
        if _is_number(attestation.get("authData")):
            return f"{path}'s authData", _BYTE_STRING
        statement = attestation.get("attStmt")
        if attestation.get("fmt") == "android-safetynet" and isinstance(statement, Mapping):
            return _in_safetynet(statement.get("response"), f"{path}'s android-safetynet response")
    return None


def _in_safetynet(response: Any, path: str) -> tuple[str, str] | None:
    parts = response.split(b".") if isinstance(response, bytes) else []
    if len(parts) != 3:
        return None
    header, payload = (_json(_as_fido2_reads(part)) for part in parts[:2])
    if isinstance(payload, dict) and _is_number(payload.get("nonce")):
        return f"{path}'s nonce", _TEXT
    certificates = header.get("x5c") if isinstance(header, dict) else None
    for index, certificate in enumerate(certificates if isinstance(certificates, list) else []):
        if _is_number(certificate):
            return f"{path}'s x5c[{index}]", _TEXT
    return None
