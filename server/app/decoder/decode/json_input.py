"""JSON that decoder input holds: the input text itself, UTF-8 JSON bytes, client data.

``json.loads`` keeps the last of an object's repeated keys and drops the rest
without a word. ``read`` gives the same value -- the later value wins -- read
with ``object_pairs_hook`` so that every repeated key is also reported, as a
``duplicate-json-key`` finding naming its path, the value kept and each value
dropped. ``object_pairs_hook`` gives no positions, so a JSON finding carries a
path and no offset (``None``).
"""
from __future__ import annotations

import json
from typing import Any


class _Members(list):
    """A JSON object's members as read: (key, value) pairs in order, a repeated key kept."""


def read(text: str) -> tuple[Any, list[dict[str, Any]]]:
    """``text`` as JSON, and a finding per repeated key; raises exactly as ``json.loads`` does."""

    findings: list[dict[str, Any]] = []
    value = _resolve(json.loads(text, object_pairs_hook=_Members), "$", findings)
    return value, findings


def read_or_none(text: Any) -> tuple[Any | None, list[dict[str, Any]]]:
    """``read``, or ``(None, [])`` for text that is not JSON."""

    try:
        return read(text)
    except (ValueError, TypeError):
        return None, []


def _try_parse_json(value: str) -> Any | None:
    return read_or_none(value)[0]


def _resolve(value: Any, path: str, findings: list[dict[str, Any]]) -> Any:
    if isinstance(value, _Members):
        resolved: dict[str, Any] = {}
        occurrences: dict[str, list[Any]] = {}
        for key, member in value:
            member_value = _resolve(member, _member_path(path, key), findings)
            occurrences.setdefault(key, []).append(member_value)
            resolved[key] = member_value
        for key, values in occurrences.items():
            if len(values) > 1:
                findings.append(_duplicate(_member_path(path, key), key, values))
        return resolved
    if isinstance(value, list):
        return [_resolve(item, f"{path}[{index}]", findings) for index, item in enumerate(value)]
    return value


def _member_path(path: str, key: str) -> str:
    return f"{path}{{{json.dumps(key, ensure_ascii=False)}}}"


def _duplicate(path: str, key: str, values: list[Any]) -> dict[str, Any]:
    kept, dropped = values[-1], values[:-1]
    times, which = ("twice", "later") if len(values) == 2 else (f"{len(values)} times", "last")
    return {
        "code": "duplicate-json-key",
        "category": "json",
        "offset": None,
        "path": path,
        "key": key,
        "kept": kept,
        "dropped": dropped,
        "message": (
            f"object key {json.dumps(key, ensure_ascii=False)} appears {times}; the decoded value keeps the "
            f"{which} value, {_short(kept)}, and drops {', '.join(_short(value) for value in dropped)}"
        ),
    }


def _short(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 40 else f"{text[:37]}..."
