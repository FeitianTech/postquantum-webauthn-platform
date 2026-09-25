"""The decoder's one CBOR parser.

Strict by default: anything that is not well-formed CBOR (RFC 8949) raises
``_CborDecodingError`` with the byte offset and the path of the item at fault.
It never guesses, never truncates and never skips.

Lenient only when a caller asks for it: the parse then keeps what is there --
the bytes a truncated string does have, the items a short array does have --
steps over bytes it cannot read, and records every such step in ``skipped``.

Every node records where it sits in the input (``offset``/``end``) and how its
head was written (``info``/``argument``), which is what the canonical-form
check in ``canonical.py`` reads. Offsets count from the start of ``data``.
"""
from __future__ import annotations

import math
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ...encoding import decode_hex, encode_base64
from ...webauthn.attestation import encode_base64url
from .. import edn
from . import key_equivalence

# Deep enough for any WebAuthn or CTAP structure; shallow enough that hostile
# input cannot exhaust the interpreter's recursion limit.
_MAX_DEPTH = 64

_MAJOR_TYPE_NAMES = {
    0: "unsigned integer",
    1: "negative integer",
    2: "byte string",
    3: "text string",
    4: "array",
    5: "map",
    6: "tag",
    7: "simple value or float",
}


class _CborDecodingError(ValueError):
    """Raised when input is not well-formed CBOR, with where it went wrong."""

    def __init__(self, message: str, offset: int, path: str = "$") -> None:
        super().__init__(f"Not well-formed CBOR at offset {offset} ({path}): {message}")
        self.reason = message
        self.offset = offset
        self.path = path


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


class _ParseState:
    __slots__ = ("data", "lenient", "skipped")

    def __init__(self, data: bytes, lenient: bool) -> None:
        self.data = data
        self.lenient = lenient
        self.skipped: list[dict[str, Any]] = []

    def problem(self, code: str, message: str, offset: int, path: str) -> None:
        """Raise in strict mode; in lenient mode, record the step and go on."""

        if not self.lenient:
            raise _CborDecodingError(message, offset, path)
        self.skipped.append(
            {"code": code, "category": "skipped", "offset": offset, "path": path, "message": message}
        )


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def _read_cbor_length(
    info: int, data: bytes, offset: int, *, allow_indefinite: bool = False
) -> tuple[int | None, int]:
    """Read an item's argument. ``offset`` is just past the initial byte."""

    if info < 24:
        return info, offset
    if info <= 27:
        size = 1 << (info - 24)
        if offset + size > len(data):
            raise _CborDecodingError(
                f"the head needs {_count(size, 'more byte')}; {len(data) - offset} remain", offset - 1
            )
        return int.from_bytes(data[offset : offset + size], "big"), offset + size
    if info == 31:
        if allow_indefinite:
            return None, offset
        raise _CborDecodingError("indefinite length is not allowed for this major type", offset - 1)
    raise _CborDecodingError(f"additional information {info} is reserved", offset - 1)


def _float_summary(value: float) -> str:
    if math.isnan(value):
        return "float(NaN)"
    if math.isinf(value):
        return "float(+Infinity)" if value > 0 else "float(-Infinity)"
    return f"float({value})"


def _text_summary(value: str) -> str:
    return f'"{value if len(value) <= 32 else value[:29] + "..."}"'


def _byte_node(raw: bytes, **fields: Any) -> dict[str, Any]:
    node: dict[str, Any] = {
        "majorType": 2,
        "type": "byte string",
        "length": len(raw),
        "hex": raw.hex(),
        "base64": encode_base64(raw),
        "base64url": encode_base64url(raw),
    }
    node.update(fields)
    node["summary"] = f"bytes[{node['length']}]"
    if "declaredLength" in node:
        node["summary"] += f" (truncated from {node['declaredLength']})"
    return node


def _invalid_node(state: _ParseState, start: int, end: int, major_type: int) -> dict[str, Any]:
    raw = state.data[start:end]
    return {
        "majorType": major_type,
        "type": "invalid",
        "hex": raw.hex(),
        "summary": f"invalid(h'{raw.hex()}')",
        "offset": start,
        "end": end,
    }


def _key_path(path: str, key_node: Mapping[str, Any]) -> str:
    return f"{path}{{{_diagnostic_key(key_node)}}}"


def _diagnostic_key(node: Mapping[str, Any]) -> str:
    """A map key in CBOR diagnostic notation, cut short: paths name, offsets locate."""

    node_type = node.get("type")
    if node_type in ("unsigned", "negative"):
        return str(node.get("value"))
    if node_type == "text string" and isinstance(node.get("value"), str):
        text = node["value"]
        return f'"{text}"' if len(text) <= 32 else f'"{text[:29]}..."'
    if node_type == "byte string":
        hex_value = str(node.get("hex", ""))
        return f"h'{hex_value}'" if len(hex_value) <= 32 else f"h'{hex_value[:16]}...'"
    return str(node.get("summary", "?"))


def _parse_cbor_item(
    data: bytes,
    offset: int,
    *,
    state: _ParseState | None = None,
    path: str = "$",
    depth: int = 0,
) -> tuple[dict[str, Any], int]:
    """Parse the item at ``offset``; return its node and the offset after it."""

    if state is None:
        state = _ParseState(data, lenient=False)
    if depth > _MAX_DEPTH:
        raise _CborDecodingError(f"items are nested more than {_MAX_DEPTH} deep", offset, path)
    if offset >= len(data):
        raise _CborDecodingError("the data ends where an item should start", offset, path)

    start = offset
    initial = data[offset]
    major_type = initial >> 5
    info = initial & 0x1F
    offset += 1

    try:
        argument, offset = _read_cbor_length(
            info, data, offset, allow_indefinite=major_type in (2, 3, 4, 5) or (major_type == 7 and info == 31)
        )
    except _CborDecodingError as exc:
        if major_type == 7 and info in (25, 26, 27):
            precision = ("half", "single", "double")[info - 25]
            message = f"a {precision}-precision float needs {1 << (info - 24)} bytes"
        else:
            message = exc.reason
        code = "reserved-additional-info" if 28 <= info <= 30 else (
            "truncated" if info <= 27 else "invalid-indefinite-length"
        )
        state.problem(code, message, start, path)
        end = len(data) if code == "truncated" else start + 1
        return _invalid_node(state, start, end, major_type), end

    head = {"offset": start, "info": info, "argument": argument}

    if major_type == 0:
        node = {"majorType": 0, "type": "unsigned", "value": argument, "summary": str(argument)}
    elif major_type == 1:
        value = -1 - argument
        node = {"majorType": 1, "type": "negative", "value": value, "summary": str(value)}
    elif major_type in (2, 3):
        node, offset = _parse_string(state, major_type, argument, offset, start, path, depth)
    elif major_type == 4:
        node, offset = _parse_array(state, argument, offset, path, depth)
    elif major_type == 5:
        node, offset = _parse_map(state, argument, offset, path, depth)
    elif major_type == 6:
        tagged_item, offset = _parse_cbor_item(data, offset, state=state, path=f"{path}<tag>", depth=depth + 1)
        node = {"majorType": 6, "type": "tag", "tag": argument, "value": tagged_item, "summary": f"tag({argument})"}
    else:
        node, offset = _parse_simple_or_float(state, info, argument, offset, start, path)

    for key, value in head.items():
        node.setdefault(key, value)
    node["end"] = offset
    return node, offset


def _parse_string(
    state: _ParseState, major_type: int, length: int | None, offset: int, start: int, path: str, depth: int
) -> tuple[dict[str, Any], int]:
    data = state.data
    kind = _MAJOR_TYPE_NAMES[major_type]

    if length is None:
        chunks: list[dict[str, Any]] = []
        while True:
            if offset >= len(data):
                state.problem("truncated", f"indefinite-length {kind} has no break byte", start, path)
                break
            if data[offset] == 0xFF:
                offset += 1
                break
            chunk_start = offset
            chunk_path = f"{path}<chunk {len(chunks)}>"
            chunk, offset = _parse_cbor_item(data, offset, state=state, path=chunk_path, depth=depth + 1)
            if chunk.get("majorType") != major_type or chunk.get("indefinite") or chunk.get("type") == "invalid":
                state.problem(
                    "invalid-indefinite-chunk",
                    f"a chunk of an indefinite-length {kind} must be a definite-length {kind}",
                    chunk_start,
                    chunk_path,
                )
                continue
            chunks.append(chunk)
        if major_type == 2:
            raw = b"".join(decode_hex(chunk["hex"]) for chunk in chunks)
            return _byte_node(raw, indefinite=True, chunks=chunks), offset
        text = "".join(chunk.get("value", "") for chunk in chunks if isinstance(chunk.get("value"), str))
        node = {
            "majorType": 3,
            "type": "text string",
            "length": len(text.encode("utf-8")),
            "value": text,
            "indefinite": True,
            "segments": chunks,
            "summary": _text_summary(text),
        }
        return node, offset

    available = len(data) - offset
    if length > available:
        state.problem("truncated", f"{kind} declares {_count(length, 'byte')}; {available} remain", start, path)
        raw = data[offset:]
        offset = len(data)
        if major_type == 2:
            return _byte_node(raw, declaredLength=length, truncated=True), offset
    else:
        raw = data[offset : offset + length]
        offset += length
        if major_type == 2:
            return _byte_node(raw), offset

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        state.problem("invalid-utf8", "text string is not valid UTF-8", start, path)
        return {
            "majorType": 3,
            "type": "text string",
            "length": len(raw),
            "hex": raw.hex(),
            "error": "Invalid UTF-8 in text string.",
            "summary": f"text[{len(raw)}]",
        }, offset
    node = {"majorType": 3, "type": "text string", "length": len(raw), "value": text, "summary": _text_summary(text)}
    if len(raw) < length:
        node.update(declaredLength=length, truncated=True)
    return node, offset


def _parse_array(
    state: _ParseState, length: int | None, offset: int, path: str, depth: int
) -> tuple[dict[str, Any], int]:
    data = state.data
    items: list[dict[str, Any]] = []
    node: dict[str, Any] = {"majorType": 4, "type": "array"}
    if length is None:
        node["indefinite"] = True
        while True:
            if offset >= len(data):
                state.problem("truncated", "indefinite-length array has no break byte", offset, path)
                break
            if data[offset] == 0xFF:
                offset += 1
                break
            item, offset = _parse_cbor_item(data, offset, state=state, path=f"{path}[{len(items)}]", depth=depth + 1)
            items.append(item)
    else:
        for index in range(length):
            if offset >= len(data):
                state.problem(
                    "truncated",
                    f"array declares {_count(length, 'item')}; the data ends after {index}",
                    offset,
                    f"{path}[{index}]",
                )
                node["declaredLength"] = length
                break
            item, offset = _parse_cbor_item(data, offset, state=state, path=f"{path}[{index}]", depth=depth + 1)
            items.append(item)
    node.update(length=len(items), items=items, summary=f"array[{len(items)}]")
    return node, offset


def _parse_map(
    state: _ParseState, length: int | None, offset: int, path: str, depth: int
) -> tuple[dict[str, Any], int]:
    data = state.data
    entries: list[dict[str, Any]] = []
    node: dict[str, Any] = {"majorType": 5, "type": "map"}
    index = 0
    while True:
        if length is None:
            if offset >= len(data):
                state.problem("truncated", "indefinite-length map has no break byte", offset, path)
                break
            if data[offset] == 0xFF:
                offset += 1
                break
        elif index >= length:
            break
        elif offset >= len(data):
            entries_text = f"{length} entry" if length == 1 else f"{length} entries"
            state.problem("truncated", f"map declares {entries_text}; the data ends after {index}", offset, path)
            node["declaredLength"] = length
            break
        key, offset = _parse_cbor_item(data, offset, state=state, path=f"{path}<key {index}>", depth=depth + 1)
        value_path = _key_path(path, key)
        if offset >= len(data) or (length is None and data[offset] == 0xFF):
            state.problem("missing-map-value", f"map key {_diagnostic_key(key)} has no value", key["offset"], value_path)
            if length is not None:
                node["declaredLength"] = length
            if offset < len(data):
                offset += 1
            break
        value, offset = _parse_cbor_item(data, offset, state=state, path=value_path, depth=depth + 1)
        entry: dict[str, Any] = {"keySummary": key.get("summary"), "key": key, "value": value, "path": value_path}
        if value.get("summary") is not None:
            entry["valueSummary"] = value["summary"]
        entries.append(entry)
        index += 1
    if length is None:
        node["indefinite"] = True
    node.update(length=len(entries), entries=entries, summary=f"map[{len(entries)}]")
    return node, offset


def _parse_simple_or_float(
    state: _ParseState, info: int, argument: int | None, offset: int, start: int, path: str
) -> tuple[dict[str, Any], int]:
    if info == 31:
        state.problem("unexpected-break", "a break byte (0xff) outside an indefinite-length item", start, path)
        return _invalid_node(state, start, offset, 7), offset
    if info in (25, 26, 27):
        raw = state.data[offset - (1 << (info - 24)) : offset]
        value = struct.unpack((">e", ">f", ">d")[info - 25], raw)[0]
        precision = ("half", "single", "double")[info - 25]
        return {"majorType": 7, "type": "float", "precision": precision, "value": value,
                "summary": _float_summary(value)}, offset
    if info == 20:
        return {"majorType": 7, "type": "boolean", "value": False, "summary": "false"}, offset
    if info == 21:
        return {"majorType": 7, "type": "boolean", "value": True, "summary": "true"}, offset
    if info == 22:
        return {"majorType": 7, "type": "null", "summary": "null"}, offset
    if info == 23:
        return {"majorType": 7, "type": "undefined", "summary": "undefined"}, offset
    if info == 24 and argument is not None and argument < 32:
        state.problem("invalid-simple-value", f"simple value {argument} must be written in one byte", start, path)
        return _invalid_node(state, start, offset, 7), offset
    return {"majorType": 7, "type": "simple", "value": argument, "summary": f"simple({argument})"}, offset


def decode_item(
    data: bytes, offset: int = 0, *, lenient: bool = False
) -> tuple[dict[str, Any], int, list[dict[str, Any]]]:
    """Parse one CBOR item starting at ``offset``.

    Returns the item's node, the offset just past it, and -- in lenient mode --
    what the parse stepped over. Bytes after the item are left to the caller.
    """

    state = _ParseState(data, lenient)
    node, end = _parse_cbor_item(data, offset, state=state)
    return node, end, state.skipped


def _decode_cbor_structure(data: bytes) -> tuple[dict[str, Any], int]:
    node, offset, _ = decode_item(data)
    node.setdefault("byteLength", offset)
    return node, offset


# The type a map key held as a CborDiagnostic is, named for a reader.
_KEY_KINDS = {"simple": "simple value", "text string": "text, not UTF-8"}


def _map_key(key_node: Mapping[str, Any]) -> Any:
    key = _structure_to_value(key_node)
    node_type = key_node.get("type")
    kind = _KEY_KINDS.get(node_type, node_type) if isinstance(node_type, str) else ""
    # A NaN key is spelled by its bits: NaNs with different payloads are different keys.
    if isinstance(key, CborDiagnostic) and key.diagnostic == "NaN":
        return _edn_or(key_node, "NaN", kind)
    # Python folds 1 == 1.0 == True, three different CBOR keys, into one.
    if key is None or isinstance(key, (bool, float)):
        return CborDiagnostic(_diagnostic_value(key_node), kind)
    if isinstance(key, CborDiagnostic):
        return CborDiagnostic(key.diagnostic, kind)
    # An array, map or tag key: a key of its own type, spelled in EDN, which
    # ``keys.read_json_key`` can read back.
    if isinstance(key, (list, dict)):
        return _edn_or(key_node, str(key_node.get("summary")), kind)
    return key


def _edn_or(node: Mapping[str, Any], fallback: str, kind: str) -> CborDiagnostic:
    """``node`` in EDN, on one line, a key of its ``kind``.

    A node the lenient parser damaged has no exact spelling: it is shown by
    ``fallback`` (its summary) as an invalid key, as an invalid node is, which
    the encoder refuses rather than rebuild as something else.
    """

    try:
        return CborDiagnostic(edn.spell(node, inline=True), kind)
    except (KeyError, TypeError, ValueError):
        return CborDiagnostic(fallback, "invalid")


def _diagnostic_value(node: Mapping[str, Any]) -> str:
    node_type = node.get("type")
    if node_type == "boolean":
        return "true" if node.get("value") else "false"
    if node_type == "null":
        return "null"
    if node_type == "float":
        value = node.get("value")
        if isinstance(value, float) and math.isnan(value):
            return "NaN"
        if isinstance(value, float) and math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
        return repr(value)
    return str(node.get("summary"))


def _structure_to_value(node: Mapping[str, Any]) -> Any:
    major_type = node.get("majorType")
    node_type = node.get("type")

    if node_type == "invalid":
        return CborDiagnostic(str(node.get("summary")))

    if major_type in (0, 1, 7):
        if node_type == "null":
            return None
        if node_type == "undefined":
            return CborDiagnostic("undefined")
        if node_type == "simple":
            return CborDiagnostic(f"simple({node.get('value')})")
        if node_type == "boolean":
            return bool(node.get("value"))
        if node_type == "float":
            value = node.get("value")
            if isinstance(value, float) and not math.isfinite(value):
                return CborDiagnostic(_diagnostic_value(node))
            return value
        return node.get("value")

    if major_type == 2:
        hex_value = node.get("hex")
        if isinstance(hex_value, str):
            try:
                return decode_hex(hex_value)
            except ValueError:
                return b""
        chunks = node.get("chunks")
        if isinstance(chunks, Sequence):
            return b"".join(
                bytes(_structure_to_value(chunk) or b"")  # type: ignore[arg-type]
                for chunk in chunks
            )
        return b""

    if major_type == 3:
        text_value = node.get("value")
        if isinstance(text_value, str):
            return text_value
        if isinstance(node.get("hex"), str):
            return CborDiagnostic(f"h'{node['hex']}' (not UTF-8)")
        return ""

    if major_type == 4:
        items = node.get("items")
        if not isinstance(items, Sequence):
            return []
        return [_structure_to_value(item) for item in items]

    if major_type == 5:
        return _map_value(node)

    if major_type == 6:
        tagged_value = node.get("value")
        converted = (
            _structure_to_value(tagged_value)
            if isinstance(tagged_value, Mapping)
            else tagged_value
        )
        return {"tag": node.get("tag"), "value": converted}

    return node.get("value")


def _map_value(node: Mapping[str, Any]) -> dict[Any, Any]:
    """A map node's entries as a dict: one entry per key.

    Keys are the same key when RFC 8949 section 5.6.1 says so, however each was
    written (``key_equivalence``): the entry is spelled as the first of them and
    holds the value of the last, which ``canonical`` reports as a duplicate.
    """

    entries = node.get("entries")
    if not isinstance(entries, Sequence):
        return {}
    result: dict[Any, Any] = {}
    spelled: dict[Any, Any] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        key_node = entry.get("key")
        value_node = entry.get("value")
        if not isinstance(key_node, Mapping):
            continue
        key = spelled.setdefault(key_equivalence.identity(key_node), _map_key(key_node))
        result[key] = (
            _structure_to_value(value_node)
            if isinstance(value_node, Mapping)
            else value_node
        )
    return result
