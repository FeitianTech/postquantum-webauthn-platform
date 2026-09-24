"""Report the maps whose keys JSON cannot tell apart.

JSON spells every map key as text, so two CBOR keys of different types can
share a spelling: the integer 1 and the text "1", the byte string h'01' and the
text "01", the float 1.5 and the text "1.5". Every view of such a map shows
each of those keys with its type (``keys.json_keys``) instead of letting one
entry replace the other; ``check`` reports each such map, with its offset and
path, so the reader knows why its keys are spelled that way.

Duplicate keys -- the same key twice -- are not this: ``canonical`` reports them.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .cbor_parser import _map_key
from .keys import key_text, qualified_key_text


def check(node: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return one ``json-key-collision`` finding per map in ``node`` that needs one."""

    findings: list[dict[str, Any]] = []
    _walk(node, "$", findings)
    return findings


def _walk(node: Any, path: str, findings: list[dict[str, Any]]) -> None:
    if not isinstance(node, Mapping) or node.get("type") == "invalid":
        return
    major_type = node.get("majorType")
    if major_type == 4:
        for index, item in enumerate(node.get("items") or []):
            _walk(item, f"{path}[{index}]", findings)
    elif major_type == 5:
        _check_map(node, path, findings)
    elif major_type == 6:
        _walk(node.get("value"), f"{path}<tag>", findings)


def _check_map(node: Mapping[str, Any], path: str, findings: list[dict[str, Any]]) -> None:
    # The keys the decoded map holds, as it holds them: a duplicate is one key.
    keys: dict[Any, None] = {}
    for entry in node.get("entries") or []:
        key_node, entry_path = entry.get("key"), entry.get("path") or path
        if isinstance(key_node, Mapping) and key_node.get("type") != "invalid":
            keys.setdefault(_map_key(key_node))
            _walk(key_node, entry_path, findings)
        _walk(entry.get("value"), entry_path, findings)

    groups: dict[str, list[Any]] = {}
    for key in keys:
        groups.setdefault(key_text(key), []).append(key)
    shared = {text: group for text, group in groups.items() if len(group) > 1}
    if not shared:
        return
    clauses = [
        f"{' and '.join(qualified_key_text(key) for key in group)} "
        f"{'both' if len(group) == 2 else 'all'} read {json.dumps(text, ensure_ascii=False)}"
        for text, group in shared.items()
    ]
    findings.append(
        {
            "code": "json-key-collision",
            "category": "rendering",
            "offset": node["offset"],
            "path": path,
            "keys": [qualified_key_text(key) for group in shared.values() for key in group],
            "message": (
                f"map keys {'; '.join(clauses)} as JSON keys; each is shown with its type "
                "so that neither entry replaces the other"
            ),
        }
    )
