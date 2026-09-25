"""Report where well-formed CBOR is not in CTAP2 canonical form.

CTAP 2.2, "Message Encoding", requires the CTAP2 canonical CBOR encoding form:
integers and lengths as short as possible, no indefinite-length items, map keys
sorted by major type, then encoded length, then bytewise, and no tags. RFC 8949
section 5.6 adds that a map with a duplicate key is not valid CBOR at all: two
keys are the same key when section 5.6.1 says so, however each was written
(``key_equivalence``). The
same section of CTAP 2.2 limits nesting to "at most four (4) levels of any
combination of CBOR maps and/or CBOR arrays"; the first map or array at a fifth
level is reported, its contents are not reported again.

``check`` walks a node tree from ``cbor_parser`` and returns one finding per
violation, each with the byte offset and path of the item at fault. It reads
the tree and the input bytes; it never changes either, or the decoded value.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .. import edn
from ..ctap2_order import ctap2_key_order
from . import key_equivalence
from .cbor_parser import _diagnostic_key

# CTAP 2.2 section 8, "Message Encoding": the deepest maps and arrays may nest.
_MAX_NESTING = 4

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
    _check_node(node, data, "$", findings, 0)
    return findings


def relocate(findings: list[dict[str, Any]], base_offset: int, path_prefix: str) -> list[dict[str, Any]]:
    """Rebase findings about CBOR held in a byte string onto the input around it.

    ``base_offset`` is where the byte string's content starts in the input and
    ``path_prefix`` names the item inside it, e.g. ``${2}<credentialPublicKey>``.
    The offsets a duplicate key's earlier entries carry move with it, and so do
    the ones its message quotes.
    """

    return [
        _with_duplicate_message(
            {
                **finding,
                "offset": finding["offset"] + base_offset,
                "path": path_prefix + finding["path"][1:],
                **({"earlier": [_moved(entry, base_offset) for entry in finding["earlier"]]}
                   if "earlier" in finding else {}),
            }
        )
        for finding in findings
    ]


def _moved(entry: Mapping[str, Any], base_offset: int) -> dict[str, Any]:
    return {**entry, "offset": entry["offset"] + base_offset, "valueOffset": entry["valueOffset"] + base_offset}


def pin_to(findings: list[dict[str, Any]], offset: int) -> list[dict[str, Any]]:
    """Findings about CBOR inside a chunked byte string, every offset pointed at the string itself.

    Its bytes are not contiguous in the input, so nothing inside it has an input
    offset of its own.
    """

    return [
        _with_duplicate_message(
            {
                **finding,
                "offset": offset,
                **({"earlier": [{**entry, "offset": offset, "valueOffset": offset} for entry in finding["earlier"]]}
                   if "earlier" in finding else {}),
            }
        )
        for finding in findings
    ]


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


def _check_node(
    node: Mapping[str, Any], data: bytes, path: str, findings: list[dict[str, Any]], depth: int
) -> None:
    """Check ``node``; ``depth`` counts the maps and arrays around it."""

    if not isinstance(node, Mapping) or node.get("type") == "invalid":
        return
    major_type = node.get("majorType")
    offset = node.get("offset")
    if major_type in (4, 5):
        depth += 1
        if depth == _MAX_NESTING + 1:
            findings.append(
                {
                    "code": "nesting-depth",
                    "category": "limit",
                    "offset": offset,
                    "path": path,
                    "message": (
                        f"{_KINDS[major_type]} nested {depth} levels deep; CTAP2 allows at most "
                        f"{_MAX_NESTING} levels of maps and arrays"
                    ),
                }
            )

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
            _check_node(chunk, data, f"{path}<chunk {index}>", findings, depth)
    elif major_type == 4:
        for index, item in enumerate(node.get("items") or []):
            _check_node(item, data, f"{path}[{index}]", findings, depth)
    elif major_type == 5:
        _check_map(node, data, path, findings, depth)
    elif major_type == 6:
        findings.append(
            _finding("tag", offset, path, f"tag {node.get('tag')}; CTAP2 canonical CBOR has no tags")
        )
        _check_node(node.get("value") or {}, data, f"{path}<tag>", findings, depth)


def _check_map(
    node: Mapping[str, Any], data: bytes, path: str, findings: list[dict[str, Any]], depth: int
) -> None:
    seen: dict[Any, list[Mapping[str, Any]]] = {}
    previous: tuple[bytes, Mapping[str, Any]] | None = None
    for entry in node.get("entries") or []:
        key, value = entry.get("key"), entry.get("value")
        if not isinstance(key, Mapping) or key.get("type") == "invalid":
            continue
        entry_path = entry.get("path") or path
        key_offset = key["offset"]
        encoded = data[key_offset : key["end"]]
        _check_node(key, data, entry_path, findings, depth)

        identity = key_equivalence.identity(key)
        if identity in seen:
            seen[identity].append(entry)
        else:
            seen[identity] = [entry]
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
        _check_node(value, data, entry_path, findings, depth)
    # One finding per repeated key, at the entry the decoded value keeps: the last.
    for occurrences in seen.values():
        if len(occurrences) > 1:
            kept = occurrences[-1]
            findings.append(_duplicate(kept["key"], kept.get("path") or path, occurrences[:-1]))


def _duplicate(key: Mapping[str, Any], path: str, earlier: list[Mapping[str, Any]]) -> dict[str, Any]:
    """The finding for ``key``, the entry the decoded value keeps, after ``earlier`` ones: each, as EDN."""

    entries = [
        {
            "offset": entry["key"]["offset"],
            "valueOffset": entry["value"]["offset"],
            "key": _edn(entry["key"]),
            "value": _edn(entry["value"]),
        }
        for entry in earlier
    ]
    finding = _finding("duplicate-map-key", key["offset"], path, "")
    finding.update(key=_diagnostic_key(key), earlier=entries, kept="later")
    return _with_duplicate_message(finding)


def _with_duplicate_message(finding: dict[str, Any]) -> dict[str, Any]:
    """A duplicate key's message, written from the finding's own fields: again whenever its offsets move."""

    if finding.get("code") != "duplicate-map-key":
        return finding
    entries = finding["earlier"]
    count = len(entries) + 1
    times, which = ("twice", "later") if count == 2 else (f"{count} times", "last")
    dropped = ", ".join(f"{_short(entry['value'])} (offset {entry['valueOffset']})" for entry in entries)
    return {
        **finding,
        "message": (
            f"map key {finding['key']} appears {times} (first at offset {entries[0]['offset']}); the decoded value "
            f"keeps this {which} entry, and drops the earlier value{'s' if len(entries) > 1 else ''} {dropped}"
        ),
    }


def _edn(node: Mapping[str, Any]) -> str:
    try:
        return edn.spell(node, inline=True)
    except (KeyError, TypeError, ValueError):
        return str(node.get("summary", "?"))


def _short(text: str) -> str:
    return text if len(text) <= 40 else f"{text[:37]}..."
