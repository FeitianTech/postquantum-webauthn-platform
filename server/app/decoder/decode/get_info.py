"""What an authenticatorGetInfo response means: CTAP 2.2 section 6.4, as ``data.getInfoDecoded``.

``ctapDecoded.getInfoResponse`` shows every member as sent (``ctap_views``), and
the encoder rebuilds it; this is beside it, labelled the same way, and says what
each member means where the spec says:

* aaguid as a GUID;
* each option ID with what its value means and the default when it is absent
  (the option table in section 6.4), including the option IDs not sent;
* each algorithm named through ``pqc.describe_algorithm``, so ML-DSA is named;
* the uvModality bits (FIDO Registry section 3.1) and the certification IDs
  (CTAP 2.2 section 7.3.1).

A member number CTAP 2.2 does not define, an option or certification ID it does
not define, and a key that is not an integer are shown as sent and labelled so;
nothing is dropped. The decoder shows the response; it checks none of the
MUSTs section 6.4 places on it.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from typing import Any

from ...webauthn import pqc
from .. import ctap_tables
from .keys import (
    MISSING,
    get_mapping_entry,
    hex_json_safe,
    json_items,
    qualified_key_text,
)

_AAGUID_LENGTH = 16


def looks_like_get_info(value: Any) -> bool:
    """The two members section 6.4 requires: versions (text array), aaguid (bytes)."""

    versions = get_mapping_entry(value, 1)
    aaguid = get_mapping_entry(value, 3)
    return (
        isinstance(versions, list)
        and bool(versions)
        and all(isinstance(version, str) for version in versions)
        and isinstance(aaguid, bytes)
    )


def interpret_get_info(value: Mapping[Any, Any]) -> dict[str, Any]:
    """``data.getInfoDecoded``: what each member means, labelled as ``ctapDecoded`` labels it."""

    interpreted: dict[str, Any] = {}
    for label, key, entry in json_items(value, _member_label):
        name = ctap_tables.GET_INFO_RESPONSE.get(key) if _is_member_number(key) else None
        if name:
            interpreted[label] = _MEMBER_VIEWS.get(name, hex_json_safe)(entry)
        else:
            note = _NOT_DEFINED if _is_member_number(key) else _NOT_A_MEMBER
            interpreted[label] = {"value": hex_json_safe(entry), "note": note}
    return interpreted


_NOT_DEFINED = "not a member CTAP 2.2 section 6.4 defines"
_NOT_A_MEMBER = "not a member: CTAP 2.2 numbers members with integer keys"


def _is_member_number(key: Any) -> bool:
    return isinstance(key, int) and not isinstance(key, bool)


def _member_label(key: Any, text: str) -> str:
    # As every CTAP view labels a member: "N (name)", the number alone, or the key with its type.
    if not _is_member_number(key):
        return qualified_key_text(key)
    name = ctap_tables.GET_INFO_RESPONSE.get(key)
    return f"{text} ({name})" if name else text


def _aaguid(value: Any) -> Any:
    if not isinstance(value, bytes):
        return hex_json_safe(value)
    view: dict[str, Any] = {"hex": value.hex()}
    if len(value) == _AAGUID_LENGTH:
        view["guid"] = str(uuid.UUID(bytes=value))
    else:
        view["note"] = f"an aaguid is {_AAGUID_LENGTH} bytes (CTAP 2.2 section 6.4); this one is {len(value)}"
    return view


def _options(value: Any) -> Any:
    if not isinstance(value, Mapping):
        return hex_json_safe(value)
    options: dict[str, Any] = {}
    for name, option, setting in json_items(value):
        known = ctap_tables.GET_INFO_OPTIONS.get(option) if isinstance(option, str) else None
        if known is None:
            options[name] = {
                "value": hex_json_safe(setting),
                "known": False,
                "meaning": "not an option ID CTAP 2.2 section 6.4 defines",
            }
            continue
        if_true, if_false, default = known
        if isinstance(setting, bool):
            meaning = if_true if setting else if_false
        else:
            meaning = "not a boolean: CTAP 2.2 option values are booleans"
        options[name] = {"value": hex_json_safe(setting), "meaning": meaning, "defaultWhenAbsent": default}
    for option, (_if_true, _if_false, default) in ctap_tables.GET_INFO_OPTIONS.items():
        if get_mapping_entry(value, option) is MISSING:
            options[option] = {"value": None, "sent": False, "meaning": f"not sent; absent means: {default}"}
    return options


def _algorithms(value: Any) -> Any:
    if not isinstance(value, list):
        return hex_json_safe(value)
    algorithms = []
    for entry in value:
        view = hex_json_safe(entry)
        alg = get_mapping_entry(entry, "alg")
        if isinstance(view, dict) and isinstance(alg, int) and not isinstance(alg, bool):
            view.setdefault("algorithm", pqc.describe_algorithm(alg))
        algorithms.append(view)
    return algorithms


def _uv_modality(value: Any) -> Any:
    if not isinstance(value, int) or isinstance(value, bool):
        return hex_json_safe(value)
    view: dict[str, Any] = {
        "value": value,
        "hex": f"0x{value:08x}",
        "methods": [name for bit, name in ctap_tables.UV_MODALITY.items() if value & bit],
    }
    unknown = value & ~sum(ctap_tables.UV_MODALITY)
    if unknown:
        view["unknownBits"] = f"0x{unknown:08x}"
    return view


def _fido_level(value: int) -> str:
    # CTAP 2.2 section 7.3.1: numbered levels are the odd numbers, "+" levels the
    # even ones, so 1 is L1, 2 is L1+, 5 is L3 and 6 is L3+.
    return f"L{(value + 1) // 2}{'+' if value % 2 == 0 else ''}"


def _certifications(value: Any) -> Any:
    if not isinstance(value, Mapping):
        return hex_json_safe(value)
    certifications: dict[str, Any] = {}
    for name, certification, level in json_items(value):
        meaning = ctap_tables.GET_INFO_CERTIFICATIONS.get(certification) if isinstance(certification, str) else None
        view: dict[str, Any] = {"value": hex_json_safe(level)}
        if meaning is None:
            view.update(known=False, meaning="not a certification ID CTAP 2.2 section 7.3.1 defines")
        else:
            view["meaning"] = meaning
            if certification == "FIDO" and isinstance(level, int) and not isinstance(level, bool) and 1 <= level <= 6:
                view["level"] = _fido_level(level)
        certifications[name] = view
    return certifications


def _text_bytes(value: Any) -> Any:
    if not isinstance(value, bytes):
        return hex_json_safe(value)
    view: dict[str, Any] = {"hex": value.hex()}
    try:
        view["text"] = value.decode("utf-8")
    except UnicodeDecodeError:
        view["note"] = "not UTF-8 text"
    return view


def _enc_identifier(value: Any) -> Any:
    if not isinstance(value, bytes):
        return hex_json_safe(value)
    return {
        "hex": value.hex(),
        "length": len(value),
        "meaning": (
            "iv || ct: a 128-bit device identifier, AES-128-CBC encrypted under a key derived from "
            "the persistentPinUvAuthToken (CTAP 2.2 section 6.4); not decrypted here"
        ),
    }


_MEMBER_VIEWS: dict[str, Callable[[Any], Any]] = {
    "aaguid": _aaguid,
    "options": _options,
    "algorithms": _algorithms,
    "uvModality": _uv_modality,
    "certifications": _certifications,
    "encIdentifier": _enc_identifier,
    "pinComplexityPolicyURL": _text_bytes,
}
