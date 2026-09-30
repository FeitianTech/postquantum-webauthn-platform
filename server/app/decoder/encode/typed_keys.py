"""The CBOR keys a JSON object's keys spell, read the way the decoder wrote them.

``decode/json_keys.read_json_key`` reads each key: a typed spelling (``"1" (text)``,
``h'01' (bytes)``, ``1.5 (float)``) is the key it names, never the literal text;
any other key is text. Two JSON keys that name the same CBOR key -- ``"a"`` and
``"a" (text)``, or two spellings of one float -- are refused, naming both:
encoding them would drop one entry, or write a map with a duplicate key.
"""
from __future__ import annotations

import json
from collections.abc import Hashable, Mapping
from typing import Any

from .. import edn, values
from ..decode.cbor_parser import decode_item
from ..decode.json_keys import read_json_key
from ..decode.key_equivalence import identity


def with_cbor_keys(value: Any, path: str = "$") -> Any:
    """``value`` with every object's keys read as the CBOR keys they spell."""

    if isinstance(value, Mapping):
        converted: dict[Any, Any] = {}
        spelled: dict[Hashable, Any] = {}
        for label, member in value.items():
            key = read_json_key(label) if isinstance(label, str) else label
            add_key(converted, spelled, key, label, path)
            converted[key] = with_cbor_keys(member, f"{path}{{{_spelling(label)}}}")
        return converted
    if isinstance(value, list):
        return [with_cbor_keys(item, f"{path}[{index}]") for index, item in enumerate(value)]
    return value


def add_key(converted: Mapping[Any, Any], spelled: dict[Hashable, Any], key: Any, label: Any, path: str) -> None:
    """Record ``key`` (spelled ``label``); refuse it if the map already holds an equivalent key."""

    same = key_identity(key)
    if same in spelled:
        raise ValueError(
            f"The keys {_spelling(spelled[same])} and {_spelling(label)} at {path} name the same CBOR key; "
            "encoding both would drop one entry. Keep one, or write the item in EDN."
        )
    spelled[same] = label


def key_identity(key: Any) -> Hashable:
    """When two keys are one key in CBOR: ``values.key_identity``, a diagnostic key the key its EDN encodes."""

    if isinstance(key, values.CborDiagnostic):
        return identity(decode_item(edn.encode(key.diagnostic))[0])
    return values.key_identity(key)


def _spelling(label: Any) -> str:
    return json.dumps(label, ensure_ascii=False) if isinstance(label, str) else repr(label)
