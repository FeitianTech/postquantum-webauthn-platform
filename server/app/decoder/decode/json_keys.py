"""A key or value spelled with its type, ``"1" (text)``, read back; and JSON keys as a person wrote them.

The spelling is ``values.qualified_key_text``'s; the encoder reads it with
``read_json_key`` and ``read_typed``.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .. import edn, values
from .cbor_parser import decode_item

# The kinds ``qualified_key_text`` writes after a key's EDN spelling, and the
# initial byte a key of each kind is encoded with.
_KINDS: dict[str, Callable[[int], bool]] = {
    "text": lambda first: first >> 5 == 3,
    "bytes": lambda first: first >> 5 == 2,
    "array": lambda first: first >> 5 == 4,
    "map": lambda first: first >> 5 == 5,
    "tag": lambda first: first >> 5 == 6,
    "boolean": lambda first: first in (0xF4, 0xF5),
    "null": lambda first: first == 0xF6,
    "undefined": lambda first: first == 0xF7,
    "float": lambda first: first in (0xF9, 0xFA, 0xFB),
    "simple value": lambda first: 0xE0 <= first <= 0xF3 or first == 0xF8,
}
# What a lenient decode spells a key it could not read with: nothing rebuilds it.
_UNREADABLE_KINDS = {"text, not UTF-8", "invalid", "diagnostic notation"}


def typed_key_kind(label: Any) -> str | None:
    """The kind ``label`` names when it is a typed key spelling ``qualified_key_text`` writes."""

    match = values.typed_spelling(label) if isinstance(label, str) else None
    return match["kind"] if match and (match["kind"] in _KINDS or match["kind"] in _UNREADABLE_KINDS) else None


def read_json_key(label: str) -> Any:
    """The CBOR map key a JSON key spells: the reader paired with ``qualified_key_text``.

    A typed spelling gives the key it spells: ``"1" (text)`` the text "1",
    ``h'01' (bytes)`` the bytes, ``1.5 (float)``, ``true (boolean)``, ``[1, 2]
    (array)`` and the rest a ``CborDiagnostic`` the canonical encoder writes from
    its EDN. Anything else is a text key, which is JSON's meaning of it: ``"1"``
    is the text "1" (the decoder's plain spelling of the integer 1 is lossy, as
    ``decodedValue`` is; its EDN is not). A label spelled like a typed key that
    names no kind this module writes, holds EDN that does not read, or is
    numbered (two keys shared the spelling) raises ``ValueError`` naming it.
    """

    if values.typed_spelling(label) is None:
        return str(label)
    try:
        return read_typed(label, noun="key")
    except TypedSpellingError as exc:
        raise _unreadable(label, exc.reason) from None


class TypedSpellingError(ValueError):
    """A typed spelling that names no value: ``reason`` says why."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def read_typed(label: str, *, noun: str = "value") -> Any:
    """The CBOR value the typed spelling ``label`` names: text, bytes, or a ``CborDiagnostic`` of its EDN.

    Raises ``TypedSpellingError`` for a numbered spelling, a kind this module does
    not write, EDN that does not read, or EDN of another kind than it says.
    """

    match = values.typed_spelling(label)
    if match is None:
        raise TypedSpellingError("it is not spelled as a typed value, <EDN> (<kind>)")
    spelling, kind = match["spelling"], match["kind"]
    if match["numbered"]:
        raise TypedSpellingError("a numbered spelling names neither of the keys that shared it; use the map's EDN")
    if kind in _UNREADABLE_KINDS:
        raise TypedSpellingError(f"the decoder could not read that {noun}; nothing rebuilds it")
    if kind not in _KINDS:
        raise TypedSpellingError(f"({kind}) is not a {noun} type; a text {noun} spelled so is written \"...\" (text)")
    try:
        encoded = edn.encode(spelling)
    except ValueError as exc:
        raise TypedSpellingError(str(exc)) from None
    if not _KINDS[kind](encoded[0]):
        raise TypedSpellingError(f"{spelling} is not a {kind}")
    if kind == "text":
        return decode_item(encoded)[0]["value"]
    if kind == "bytes":
        return bytes.fromhex(decode_item(encoded)[0]["hex"])
    return values.CborDiagnostic(spelling, kind)


def _unreadable(label: str, reason: str) -> ValueError:
    return ValueError(f"The key {json.dumps(label, ensure_ascii=False)} is not a key the encoder can read: {reason}.")


def as_written(value: Any) -> Any:
    """``value`` read from JSON, every object key in it a label as a person wrote it.

    The encoder shows back what it was given (a pasted ``ctapDecoded``, a JSON
    document, client data): each key as it was written, never spelled again as
    though it were a CBOR text key the decoder read (``json_keys``). Where the
    encoder needs the CBOR key a label spells, it reads it with ``read_json_key``.
    """

    if isinstance(value, dict):
        return {values.JsonLabel(key) if isinstance(key, str) else key: as_written(entry) for key, entry in value.items()}
    if isinstance(value, list):
        return [as_written(item) for item in value]
    return value
