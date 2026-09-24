"""Report where well-formed CBOR is not in CTAP2 canonical form.

CTAP 2.2, "Message Encoding", requires the CTAP2 canonical CBOR encoding form:
integers and lengths as short as possible, no indefinite-length items, map keys
sorted by major type, then encoded length, then bytewise, and no tags. RFC 8949
section 5.6 adds that a map with a duplicate key is not valid CBOR at all.

``check`` walks a node tree from ``cbor_parser`` and returns one finding per
violation, each with the byte offset and path of the item at fault. It reads
the tree and the input bytes; it never changes either, or the decoded value.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..ctap2_order import ctap2_key_order
from .cbor_parser import _diagnostic_key

_KINDS = {
    0: "integer",
    1: "integer",
    2: "byte string",
    3: "text string",
    4: "array",
    5: "map",
    6: "tag",
}


def check(node: Mapping[str, Any], data: bytes) -> list[dict[str, Any]]:
    """Return the CTAP2 canonical-form violations in ``node``, in byte order."""

    findings: list[dict[str, Any]] = []
    _check_node(node, data, "$", findings)
    return findings


def _finding(code: str, offset: int, path: str, message: str) -> dict[str, Any]:
    return {"code": code, "category": "canonical", "offset": offset, "path": path, "message": message}


def _head_size(info: int) -> int:
    return 1 if info < 24 else 1 + (1 << (info - 24))


def _shortest_head_size(argument: int) -> int:
    if argument < 24:
        return 1
    if argument <= 0xFF:
        return 2
    if argument <= 0xFFFF:
        return 3
    if argument <= 0xFFFFFFFF:
        return 5
    return 9


def _bytes(count: int) -> str:
    return "1 byte" if count == 1 else f"{count} bytes"


def _check_head(node: Mapping[str, Any], data: bytes, path: str, findings: list[dict[str, Any]]) -> None:
    major_type = node.get("majorType")
    info, argument, offset = node.get("info"), node.get("argument"), node.get("offset")
    if major_type not in _KINDS or not isinstance(info, int) or not isinstance(argument, int):
        return
    written, shortest = _head_size(info), _shortest_head_size(argument)
    if written == shortest:
        return
    head = data[offset : offset + written].hex(" ")
    if major_type in (0, 1):
        code, what = "non-shortest-integer", f"integer {node.get('value')}"
    elif major_type == 6:
        code, what = "non-shortest-argument", f"tag number {argument}"
    else:
        code, what = "non-shortest-length", f"{_KINDS[major_type]} of length {argument}"
    findings.append(
        _finding(
            code,
            offset,
            path,
            f"{what} has a {written}-byte head ({head}); CTAP2 requires the shortest, {_bytes(shortest)}",
        )
    )


def _check_node(node: Mapping[str, Any], data: bytes, path: str, findings: list[dict[str, Any]]) -> None:
    if not isinstance(node, Mapping) or node.get("type") == "invalid":
        return
    major_type = node.get("majorType")
    offset = node.get("offset")

    if node.get("indefinite"):
        findings.append(
            _finding(
                "indefinite-length",
                offset,
                path,
                f"indefinite-length {_KINDS[major_type]}; CTAP2 requires definite lengths",
            )
        )
    else:
        _check_head(node, data, path, findings)

    if major_type in (2, 3):
        for index, chunk in enumerate(node.get("chunks") or node.get("segments") or []):
            _check_node(chunk, data, f"{path}<chunk {index}>", findings)
    elif major_type == 4:
        for index, item in enumerate(node.get("items") or []):
            _check_node(item, data, f"{path}[{index}]", findings)
    elif major_type == 5:
        _check_map(node, data, path, findings)
    elif major_type == 6:
        findings.append(
            _finding("tag", offset, path, f"tag {node.get('tag')}; CTAP2 canonical CBOR has no tags")
        )
        _check_node(node.get("value") or {}, data, f"{path}<tag>", findings)


def _key_identity(key: Mapping[str, Any], encoded: bytes) -> tuple[Any, ...]:
    """What makes two map keys the same key, however each was written."""

    key_type = key.get("type")
    if key_type in ("unsigned", "negative"):
        return ("integer", key.get("value"))
    if key_type == "text string" and not key.get("indefinite"):
        return ("text", key.get("value"))
    if key_type == "byte string":
        return ("bytes", key.get("hex"))
    return ("encoded", encoded)


def _check_map(node: Mapping[str, Any], data: bytes, path: str, findings: list[dict[str, Any]]) -> None:
    seen: dict[tuple[Any, ...], int] = {}
    previous: tuple[bytes, Mapping[str, Any]] | None = None
    for entry in node.get("entries") or []:
        key, value = entry.get("key"), entry.get("value")
        if not isinstance(key, Mapping) or key.get("type") == "invalid":
            continue
        entry_path = entry.get("path") or path
        key_offset = key["offset"]
        encoded = data[key_offset : key["end"]]
        _check_node(key, data, entry_path, findings)

        identity = _key_identity(key, encoded)
        if identity in seen:
            findings.append(
                _finding(
                    "duplicate-map-key",
                    key_offset,
                    entry_path,
                    f"map key {_diagnostic_key(key)} appears twice (first at offset {seen[identity]}); "
                    "the decoded value keeps this later entry",
                )
            )
        else:
            seen[identity] = key_offset
            if previous is not None and ctap2_key_order(encoded) < ctap2_key_order(previous[0]):
                findings.append(
                    _finding(
                        "map-key-order",
                        key_offset,
                        entry_path,
                        f"map key {_diagnostic_key(key)} comes after {_diagnostic_key(previous[1])}; "
                        "CTAP2 sorts keys by major type, then encoded length, then bytes",
                    )
                )
        previous = (encoded, key)
        _check_node(value, data, entry_path, findings)
