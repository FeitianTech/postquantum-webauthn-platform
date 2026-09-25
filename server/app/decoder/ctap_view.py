"""The one spelling of a value inside a CTAP view (``ctapDecoded``, ``expandedJson``), and its exact reader.

``decodedValue`` is JSON, and lossy by nature: bytes and text look alike, an
integer map key reads back as text. A CTAP view has to come back to the bytes
it was read from, so its values are spelled by one rule the encoder reads back
exactly, and never guessed at:

- a byte string is its lowercase hex;
- text is itself, unless it would read as something else -- an even number of
  hexadecimal digits (``""`` too), or a typed spelling -- when it is written
  ``"<text>" (text)``: the SafetyNet ``ver`` "14574037" is ``"14574037" (text)``;
- null is null, and never dropped; booleans and integers are JSON's;
- a float, a tag, a simple value and undefined are their exact EDN with their
  type, ``"1.5 (float)"``, ``"2(h'01') (tag)"``, ``"simple(16) (simple value)"``;
- an array is a list of values; a map is an object, keyed so:
  - an integer by its number, ``"1"`` (unlike ``decodedValue`` and the
    encoder's plain JSON input, where ``"1"`` is the text "1");
  - text by itself, unless it is spelled like an integer, a typed spelling or
    a numbered label (``"a #2"``), when it is ``"<text>" (text)``;
  - anything else with its type, always: ``"h'01' (bytes)"``, ``"true (boolean)"``.

What the reader cannot read -- a JSON number with a fraction or exponent, an
integer beyond 64 bits, a key like ``"01"``, a numbered or unknown spelling --
it refuses, naming the JSON path.

The spelling is made from the parser's nodes, so a value's EDN is exact. What
no JSON view carries -- a head's width, an indefinite length, a map's order, a
repeated key -- the decoder's own check (``decode/ctap_self_check.py``) finds,
and the view is marked as one the encoder cannot rebuild.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from . import edn
from .decode import keys

# Text the reader would take for bytes: an even number of hexadecimal digits.
_HEX_BYTES = re.compile(r"(?:[0-9A-Fa-f]{2})*")
# A map key the reader takes for an integer, and what looks like one but is not canonical.
_INTEGER_KEY = re.compile(r"-?(?:0|[1-9][0-9]*)")
_DIGITS_KEY = re.compile(r"-?[0-9]+")
# A label numbered because keys the decoder counts as one shared it; text spelled so is typed.
_NUMBERED = re.compile(r".+ #[0-9]+", re.DOTALL)
_INT_RANGE = (-(2**64), 2**64 - 1)
# The type a node is written with, for what JSON has no spelling of.
_TYPED_KINDS = {"float": "float", "tag": "tag", "undefined": "undefined", "simple": "simple value"}


def spell(node: Mapping[str, Any]) -> Any:
    """The CTAP-view spelling of the value ``node`` holds (a node of ``decode/cbor_parser``)."""

    if node.get("type") == "invalid" or "error" in node or node.get("damaged"):
        # A lenient read's damage: shown by what and where it is; nothing reads it back.
        return f"invalid({node.get('summary')} at offset {node.get('offset')}) (invalid)"
    major = node.get("majorType")
    if major in (0, 1):
        return node["value"]
    if major == 2:
        return node["hex"]
    if major == 3:
        return spell_text(node["value"])
    if major == 4:
        return [spell(item) for item in node.get("items") or []]
    if major == 5:
        return spell_map(node)
    node_type = node.get("type")
    if node_type == "boolean":
        return bool(node.get("value"))
    if node_type == "null":
        return None
    return f"{edn.spell(node, inline=True)} ({_TYPED_KINDS.get(node_type, node_type)})"


def spell_text(text: str) -> str:
    """Text as itself, unless the reader would take it for bytes or a typed spelling."""

    if _HEX_BYTES.fullmatch(text) or keys.typed_spelling(text):
        return f"{json.dumps(text, ensure_ascii=False)} (text)"
    return text


def spell_map(node: Mapping[str, Any]) -> dict[str, Any]:
    """A map node as a JSON object: every entry, each key by ``key_label``."""

    spelled: dict[str, Any] = {}
    for entry in node.get("entries") or []:
        label, number = key_label(entry["key"]), 1
        while (candidate := label if number == 1 else f"{label} #{number}") in spelled:
            # Keys the decoder counts as one (a repeated key): the view cannot
            # hold both, and the check marks it; the later is numbered, not lost.
            number += 1
        spelled[candidate] = spell(entry["value"])
    return spelled


def key_label(node: Mapping[str, Any]) -> str:
    """How a map key is written: an integer by its number, text plainly where it can be, the rest typed."""

    if node.get("type") == "invalid" or "error" in node or node.get("damaged"):
        return f"invalid({node.get('summary')} at offset {node.get('offset')}) (invalid)"
    major = node.get("majorType")
    if major in (0, 1):
        return str(node["value"])
    if major == 3:
        text = node["value"]
        if _DIGITS_KEY.fullmatch(text) or _NUMBERED.fullmatch(text) or keys.typed_spelling(text):
            return f"{json.dumps(text, ensure_ascii=False)} (text)"
        return text
    if major == 2:
        return f"h'{node['hex']}' (bytes)"
    kind = {4: "array", 5: "map"}.get(major) or {"boolean": "boolean", "null": "null"}.get(node.get("type"))
    return f"{edn.spell(node, inline=True)} ({kind or _TYPED_KINDS.get(node.get('type'), node.get('type'))})"


def read(value: Any, path: str = "$") -> Any:
    """The value a CTAP-view spelling names, for the canonical writer; raises naming ``path``."""

    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not _INT_RANGE[0] <= value <= _INT_RANGE[1]:
            raise ValueError(f"{path}: {value} is beyond what a CBOR integer holds (64 bits).")
        return value
    if isinstance(value, float):
        raise ValueError(
            f"{path}: {value!r} is a JSON number with a fraction or exponent; a CTAP view writes a float "
            'with its type, as "1.5 (float)".'
        )
    if isinstance(value, str):
        return read_text(value, path)
    if isinstance(value, list):
        return [read(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, Mapping):
        return {
            read_key(label, path): read(entry, f"{path}{{{json.dumps(label, ensure_ascii=False)}}}")
            for label, entry in value.items()
        }
    raise ValueError(f"{path}: a {type(value).__name__} is no value a CTAP view writes.")


def read_text(value: str, path: str = "$") -> Any:
    """A string of a CTAP view: a typed spelling's value, bytes from hex, else the text itself."""

    if keys.typed_spelling(value):
        try:
            return keys.read_typed(value)
        except keys.TypedSpellingError as exc:
            raise ValueError(f"{path}: {json.dumps(value, ensure_ascii=False)} is no value the encoder can read: {exc.reason}.") from None
    if _HEX_BYTES.fullmatch(value):
        return bytes.fromhex(value)
    return value


def read_key(label: str, path: str = "$") -> Any:
    """A map key of a CTAP view: an integer from its number, a typed spelling's key, else the text."""

    if keys.typed_spelling(label):
        return keys.read_json_key(label)
    if _NUMBERED.fullmatch(label):
        raise ValueError(
            f"{path}: the key {json.dumps(label, ensure_ascii=False)} is numbered: keys that are one key "
            "shared its spelling, and a view cannot hold both; encode the item's EDN."
        )
    if _INTEGER_KEY.fullmatch(label):
        number = int(label)
        if not _INT_RANGE[0] <= number <= _INT_RANGE[1]:
            raise ValueError(f"{path}: the key {label} is beyond what a CBOR integer holds (64 bits).")
        return number
    if _DIGITS_KEY.fullmatch(label):
        raise ValueError(
            f'{path}: the key "{label}" is no integer a CTAP view writes (it writes {int(label)}); '
            f'the text key is written "\\"{label}\\" (text)".'
        )
    return label
