"""The decoder's value helpers, shared by the decoder and the encoder.

A leaf: it imports nothing from the decoder. Map keys: their identity
(``key_identity``, ``get_mapping_entry``) and their JSON spelling (``key_text``,
``qualified_key_text``, ``json_keys``); values made JSON-ready (``json_ready``,
``make_hex_only``, ``stringify_mapping_keys``); a byte string's summary
(``binary_summary``); and ``CborDiagnostic``, a value JSON cannot spell.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from fido2.utils import ByteBuffer

from .. import json_values
from ..encoding import encode_base64, encode_base64url

MISSING = object()

# "<spelling> (<kind>)", perhaps numbered " #2" -- where the spelling starts as an
# EDN literal does, so that "Temperature (C)" stays a text key.
_TYPED_SPELLING = re.compile(r"(?P<spelling>.+) \((?P<kind>[^()]+)\)(?P<numbered> #[0-9]+)?", re.DOTALL)
# NaN and Infinity may carry a width, NaN_2 (fa7fc00000); invalid(...) is how a
# lenient decode names a key it could not read.
_EDN_LITERAL_START = re.compile(
    r"""["'\[{0-9-]|h'|float'|simple\(|invalid\(|(?:true|false|null|undefined|(?:NaN|Infinity)(?:_[0-3])?)(?![A-Za-z0-9_])"""
)


@dataclass(frozen=True)
class CborDiagnostic:
    """A CBOR value JSON has no spelling for, in CBOR diagnostic notation.

    ``undefined``, ``simple(16)``, ``NaN`` and ``Infinity`` are values JSON
    cannot hold; ``true``, ``null`` and ``1.5`` become one of these when they
    are map keys, so that Python does not fold them into the integer 1 or 0,
    and so do array, map and tag keys, which Python cannot use as keys at all.
    """

    diagnostic: str
    #: What a map key spelled this way is ("boolean", "float", "array"), so a key
    #: that JSON would spell like a text key can be shown with its type. Empty
    #: for a value.
    kind: str = ""

    def __str__(self) -> str:
        return self.diagnostic


def key_identity(key: Any) -> tuple[str, Any]:
    """What makes a map key the key it is: its CBOR type and its value (RFC 8949 section 5.6.1).

    1, "1" and h'01' are three different CBOR map keys; Python would still fold
    1 and True together, so a bool never stands in for an integer. The labels are
    ``decode.key_equivalence.identity``'s, so a key compares with a decoded key node's.
    """

    if isinstance(key, bool):
        return ("simple", 21 if key else 20)
    if isinstance(key, int):
        return ("integer", key)
    if isinstance(key, str):
        return ("text", key)
    raw = json_values.as_bytes(key)
    if raw is not None:
        return ("bytes", raw.hex())
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
    raw = json_values.as_bytes(key)
    if raw is not None:
        return f"h'{raw.hex()}' (bytes)"
    if isinstance(key, CborDiagnostic):
        return f"{key.diagnostic} ({key.kind or 'diagnostic notation'})"
    return f"{key} ({type(key).__name__})"


def typed_spelling(label: str) -> re.Match[str] | None:
    """The parts of ``label`` if it is spelled like a typed key: an EDN literal, then `` (<kind>)``."""

    match = _TYPED_SPELLING.fullmatch(label)
    return match if match and _EDN_LITERAL_START.match(match["spelling"]) else None


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
    # A text key spelled like a typed key ("1" (text), 1 (fmt)) is spelled with
    # its type, so that read_json_key reads it back as the text it is.
    clashing |= {
        index
        for index, key in enumerate(keys)
        if isinstance(key, str) and not isinstance(key, JsonLabel) and typed_spelling(key)
    }
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


def binary_summary(data: bytes, encoding: str | None = None) -> dict[str, Any]:
    summary = {
        "length": len(data),
        "base64": encode_base64(data),
        "base64url": encode_base64url(data),
        "hex": data.hex(),
        "colonHex": data.hex(":"),
    }
    if encoding:
        summary["encoding"] = encoding
    return summary


def try_decode_utf8(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None
