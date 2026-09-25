"""Key and binary coercion helpers for decoder internals."""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from fido2.utils import ByteBuffer

from .cbor_parser import CborDiagnostic

MISSING = object()


def key_identity(key: Any) -> tuple[str, Any]:
    """What makes a map key the key it is: its CBOR type and its value.

    1, "1" and h'01' are three different CBOR map keys; Python would still fold
    1 and True together, so a bool never stands in for an integer.
    """

    if isinstance(key, bool):
        return ("bool", key)
    if isinstance(key, int):
        return ("int", key)
    if isinstance(key, str):
        return ("text", key)
    if isinstance(key, ByteBuffer):
        return ("bytes", key.getvalue())
    if isinstance(key, (bytes, bytearray, memoryview)):
        return ("bytes", bytes(key))
    return ("other", key)


def get_mapping_entry(mapping: Mapping[Any, Any], *keys: Any) -> Any:
    """Return the value under the first of ``keys`` the map has, by exact key type.

    CTAP numbers its members with integer keys: only the integer 1 is member 1,
    never a text "1" or a byte string h'01'.
    """

    if not isinstance(mapping, Mapping):
        return MISSING

    entries: dict[tuple[str, Any], Any] = {}
    for key, value in mapping.items():
        entries.setdefault(key_identity(key), value)
    for key in keys:
        candidate = entries.get(key_identity(key), MISSING)
        if candidate is not MISSING:
            return candidate
    return MISSING


def coerce_cbor_bytes(value: Any) -> bytes | None:
    if isinstance(value, ByteBuffer):
        return value.getvalue()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return None


def key_text(key: Any) -> str:
    """Spell a map key for JSON: a byte string as hex, like a byte string value."""

    if isinstance(key, ByteBuffer):
        return key.getvalue().hex()
    if isinstance(key, (bytes, bytearray, memoryview)):
        return bytes(key).hex()
    return str(key)


def qualified_key_text(key: Any) -> str:
    """Spell a map key with its type: 1, "1" (text), h'01' (bytes), true (boolean).

    For a map whose keys ``key_text`` would spell alike. An integer keeps its
    plain spelling: no other integer has it, and JSON has no other for it.
    """

    if isinstance(key, bool):
        return f"{'true' if key else 'false'} (boolean)"
    if isinstance(key, int):
        return str(key)
    if isinstance(key, str):
        return f"{json.dumps(key, ensure_ascii=False)} (text)"
    raw = coerce_cbor_bytes(key)
    if raw is not None:
        return f"h'{raw.hex()}' (bytes)"
    if isinstance(key, CborDiagnostic):
        return f"{key.diagnostic} ({key.kind or 'diagnostic notation'})"
    return f"{key} ({type(key).__name__})"


class JsonLabel(str):
    """A map key ``json_keys`` has already spelled for JSON.

    The decoder passes one map through ``json_items`` more than once (the
    decoded value, then the response); a label from an earlier pass is kept as
    it is, never spelled again as though it were a text key of the input.
    """

    __slots__ = ()


def json_keys(keys: Sequence[Any], decorate: Callable[[Any, str], str] | None = None) -> list[str]:
    """The JSON key each of a map's ``keys`` is shown under; no two are alike.

    JSON spells every key as text, so CBOR keys of different types can share a
    spelling: the integer 1 and the text "1", the byte string h'01' and the text
    "01". Where nothing collides, a key is ``key_text(key)``, passed through
    ``decorate(key, text)`` when given (a CTAP label, say). Every key whose
    spelling another key shares is spelled with its type instead
    (``qualified_key_text``), so no entry is lost to another.
    """

    def spell(key: Any, text: str) -> str:
        if isinstance(key, JsonLabel):
            return key
        return decorate(key, text) if decorate is not None else text

    labels = [spell(key, key_text(key)) for key in keys]
    clashing = _clashing([key_text(key) for key in keys]) | _clashing(labels)
    qualified: set[int] = set()
    def respellable(index: int) -> bool:
        return not _is_int(keys[index]) and not isinstance(keys[index], JsonLabel)

    while todo := {index for index in clashing - qualified if respellable(index)}:
        for index in todo:
            labels[index] = spell(keys[index], qualified_key_text(keys[index]))
        qualified |= todo
        clashing = _clashing(labels)

    # Typed spellings differ for different keys; should ``decorate`` still make
    # two alike, the later is numbered rather than lost.
    used: set[str] = set()
    for index, label in enumerate(labels):
        candidate, number = label, 1
        while candidate in used:
            number += 1
            candidate = f"{label} #{number}"
        labels[index] = JsonLabel(candidate)
        used.add(candidate)
    return labels


def json_items(
    mapping: Mapping[Any, Any], decorate: Callable[[Any, str], str] | None = None
) -> list[tuple[str, Any, Any]]:
    """Each entry of ``mapping`` as (JSON key, key, value), JSON keys by ``json_keys``."""

    keys = list(mapping)
    return [(label, key, mapping[key]) for label, key in zip(json_keys(keys, decorate), keys)]


def _is_int(key: Any) -> bool:
    return isinstance(key, int) and not isinstance(key, bool)


def _clashing(labels: Sequence[str]) -> set[int]:
    counts = Counter(labels)
    return {index for index, label in enumerate(labels) if counts[label] > 1}


def stringify_mapping_keys(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {label: stringify_mapping_keys(entry) for label, _key, entry in json_items(value)}
    if isinstance(value, list):
        return [stringify_mapping_keys(item) for item in value]
    return value


def json_ready(value: Any) -> Any:
    """``value`` with every map in it one JSON can hold whole.

    A map keyed only by text, or only by integers, is kept as it is: the JSON
    encoder spells an integer key itself. Any other map -- integer and text keys
    together, byte-string or CBOR-diagnostic keys -- is spelled by ``json_keys``,
    so no entry is lost and the response still serializes.
    """

    if isinstance(value, Mapping):
        keys = list(value)
        if all(isinstance(key, str) for key in keys) or all(_is_int(key) for key in keys):
            return {key: json_ready(entry) for key, entry in value.items()}
        return {label: json_ready(entry) for label, _key, entry in json_items(value)}
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    return value


def make_hex_only(value: Any) -> Any:
    if isinstance(value, CborDiagnostic):
        return {"diagnostic": value.diagnostic}
    if isinstance(value, ByteBuffer):
        return value.getvalue().hex()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, Mapping):
        return {label: make_hex_only(entry) for label, _key, entry in json_items(value)}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [make_hex_only(item) for item in value]
    return value


def hex_json_safe(value: Any) -> Any:
    return make_hex_only(value)
