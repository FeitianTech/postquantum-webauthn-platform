"""A CBOR item, from the decoder's parse tree, in extended diagnostic notation.

The text describes the bytes exactly (RFC 8949 section 8 and 8.1): integer and
text keys are told apart, byte strings are ``h'..'``, and wherever the input is
not in preferred serialization an encoding indicator says how it was written --
``_0``..``_3`` for a head's argument width, ``_`` for an indefinite length,
``_1``..``_3`` for a float's width. Map entries keep their order and their
duplicates. Reading the text back with :func:`..edn.encode` gives the same bytes.

The node is the one ``decode/cbor_parser`` builds; a node the lenient parser
damaged (truncated, invalid, with items dropped) cannot be spelled exactly and
raises ``ValueError``. Not every damage marks the node -- a map key whose value
is missing, a chunk skipped, a break byte absent -- so the text is read back and
must span as many bytes as the node does.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ..cbor_head import INDEFINITE, shortest_info
from . import floats, strings
from .reader import encode

_INDENT = "  "


def spell(node: Mapping[str, Any], *, inline: bool = False) -> str:
    """``node`` as EDN; ``inline`` keeps it on one line (a container of containers otherwise spans several)."""

    text = _item(node, 0, inline)
    offset, end = node.get("offset"), node.get("end")
    if isinstance(offset, int) and isinstance(end, int) and len(encode(text)) != end - offset:
        raise ValueError("the lenient parser dropped or supplied bytes that no spelling of this item shows")
    return text


def _item(node: Mapping[str, Any], depth: int, inline: bool) -> str:
    if not isinstance(node, Mapping):
        raise ValueError("not a parsed CBOR item")
    if node.get("type") == "invalid" or node.get("truncated") or "declaredLength" in node or "error" in node:
        raise ValueError("an item the lenient parser could not read whole has no exact spelling")
    major_type = node.get("majorType")
    if major_type in (0, 1):
        return _integer(node)
    if major_type == 2:
        return _string(node, "chunks", "''_", lambda chunk: f"h'{chunk['hex']}'", lambda chunk: len(chunk["hex"]) // 2)
    if major_type == 3:
        return _string(node, "segments", '""_', lambda chunk: strings.quote(chunk["value"]), _utf8_length)
    if major_type == 4:
        return _array(node, depth, inline)
    if major_type == 5:
        return _map(node, depth, inline)
    if major_type == 6:
        tag = node["tag"]
        return f"{tag}{_indicator(node, tag)}({_item(node['value'], depth, inline)})"
    if major_type == 7:
        return _simple(node)
    raise ValueError(f"no CBOR major type {major_type!r}")


def _indicator(node: Mapping[str, Any], argument: int) -> str:
    """``_0``..``_3`` where the head is wider than the argument needs; nothing where it is not."""

    info = node.get("info")
    if not isinstance(info, int) or info < 24 or info == shortest_info(argument):
        return ""
    return f"_{info - 24}"


def _is_indefinite(node: Mapping[str, Any]) -> bool:
    return bool(node.get("indefinite")) or node.get("info") == INDEFINITE


def _integer(node: Mapping[str, Any]) -> str:
    value = node["value"]
    argument = value if node["majorType"] == 0 else -1 - value
    return f"{value}{_indicator(node, argument)}"


def _utf8_length(node: Mapping[str, Any]) -> int:
    return len(node["value"].encode("utf-8"))


def _string(
    node: Mapping[str, Any],
    chunk_key: str,
    empty_indefinite: str,
    literal: Callable[[Mapping[str, Any]], str],
    length: Callable[[Mapping[str, Any]], int],
) -> str:
    if _is_indefinite(node):
        chunks = node.get(chunk_key) or []
        if not chunks:
            return empty_indefinite
        return "(_ " + ", ".join(_string(chunk, chunk_key, empty_indefinite, literal, length) for chunk in chunks) + ")"
    return f"{literal(node)}{_indicator(node, length(node))}"


def _array(node: Mapping[str, Any], depth: int, inline: bool) -> str:
    items: Sequence[Mapping[str, Any]] = node.get("items") or []
    _check_count(node, len(items))
    parts = [_item(item, depth + 1, inline) for item in items]
    nested = any(item.get("majorType") in (4, 5) for item in items)
    return _container("[", "]", parts, _container_indicator(node, len(items)), nested and not inline, depth)


def _map(node: Mapping[str, Any], depth: int, inline: bool) -> str:
    entries: Sequence[Mapping[str, Any]] = node.get("entries") or []
    _check_count(node, len(entries))
    parts = [
        f"{_item(entry['key'], depth + 1, True)}: {_item(entry['value'], depth + 1, inline)}" for entry in entries
    ]
    nested = any(entry["value"].get("majorType") in (4, 5) for entry in entries)
    return _container("{", "}", parts, _container_indicator(node, len(entries)), nested and not inline, depth)


def _check_count(node: Mapping[str, Any], count: int) -> None:
    # A lenient parse can drop an entry (a key with no value) without marking the node.
    argument = node.get("argument")
    if not _is_indefinite(node) and isinstance(argument, int) and argument != count:
        raise ValueError(f"a container that declares {argument} items holds {count}")


def _container_indicator(node: Mapping[str, Any], count: int) -> str:
    return "_" if _is_indefinite(node) else _indicator(node, count)


def _container(opening: str, closing: str, parts: list[str], indicator: str, multiline: bool, depth: int) -> str:
    head = opening + indicator
    if not parts:
        # ``[_ ]`` (RFC 8949's empty indefinite array), ``[_0]``, ``[]``.
        return head + (" " if indicator == "_" else "") + closing
    if not multiline:
        # An indicator is followed by blank space before the first item.
        return head + (" " if indicator else "") + ", ".join(parts) + closing
    pad = _INDENT * (depth + 1)
    return head + "\n" + ",\n".join(pad + part for part in parts) + "\n" + _INDENT * depth + closing


def _simple(node: Mapping[str, Any]) -> str:
    kind = node.get("type")
    if kind == "float" or "precision" in node or node.get("info") in (25, 26, 27):
        return floats.spell(node)
    if kind == "boolean":
        return "true" if node.get("value") else "false"
    if kind in ("null", "undefined"):
        return kind
    if kind == "simple":
        return f"simple({node['value']})"
    raise ValueError(f"no spelling for a major-type-7 item of type {kind!r}")
