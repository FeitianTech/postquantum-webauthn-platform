"""JSON that decoder input holds: the input text itself, UTF-8 JSON bytes, client data.

``json.loads`` keeps the last of an object's repeated keys and drops the rest
without a word. ``read`` gives the same value -- the later value wins -- read
with ``object_pairs_hook`` so that every repeated key is also reported, as a
``duplicate-json-key`` finding naming its path, the value kept and each value
dropped -- or, inside a value that is itself dropped for a later repeat of its
key, that none is kept. ``object_pairs_hook`` gives no positions, so a JSON
finding carries a path and no offset (``None``).

Python's reader also accepts ``NaN``, ``Infinity`` and ``-Infinity``, which RFC
8259 does not: text holding one is not JSON. Read strictly, it raises
``JsonConstantError`` with the offset and path of the first; read leniently,
each is a ``json-nan-or-infinity`` finding with its offset and path, and is
shown as the decoder shows such a CBOR float, ``{"diagnostic": "NaN"}`` -- never
as a bare ``NaN``, which would make the decoder's own answer not JSON.

Every value counts against the request's item budget (``item_budget``), named
by its path and no offset, as a finding is. ``json.loads`` has read the whole
text by then: the request's size limit bounds what that costs.

JSON is read at most 64 deep, as CBOR and EDN are (RFC 8259 section 9 lets a
parser limit how deep it reads): a value nested deeper raises ``JsonDepthError``
with the offset and path of the first, strict or lenient. ``json.loads`` itself
reads as deep as the text goes until Python's stack runs out, so both that and
``_resolve`` stopping at the limit are refused at that first value.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from .. import item_budget

# decode/cbor_parser's limit, which edn/reader keeps too: JSON is read as deep as CBOR is.
_MAX_DEPTH = 64


class _Members(list):
    """A JSON object's members as read: (key, value) pairs in order, a repeated key kept."""


class _Constant(str):
    """``NaN``, ``Infinity`` or ``-Infinity`` where the text held it: not JSON."""


class JsonConstantError(ValueError):
    """Text Python's JSON reader accepts only by its extension: ``NaN``, ``Infinity``, ``-Infinity``."""

    def __init__(self, constant: str, path: str, offset: int) -> None:
        self.offset, self.path = offset, path
        self.reason = f"{constant} is not JSON: RFC 8259 has no NaN or Infinity"
        super().__init__(
            f"Not JSON at offset {offset} ({path}): {self.reason}. The decoder reads it when asked to read "
            "leniently; EDN writes it (NaN, Infinity, -Infinity)."
        )


class JsonDepthError(ValueError):
    """JSON nested deeper than the decoder reads: where the first value too deep starts."""

    def __init__(self, path: str, offset: int) -> None:
        self.offset, self.path = offset, path
        self.reason = f"values are nested more than {_MAX_DEPTH} deep, the most the decoder reads"
        super().__init__(f"JSON nested too deep at offset {offset} ({path}): {self.reason}")


class _TooDeep(Exception):
    """``_resolve`` met a value nested deeper than ``_MAX_DEPTH``: ``_read`` finds where it starts."""


def read(
    text: str, *, lenient: bool = False, base: int = 0, in_bytes: bool = False
) -> tuple[Any, list[dict[str, Any]]]:
    """``text`` as JSON, and its findings; raises as ``json.loads`` does, and for NaN or Infinity unless ``lenient``.

    Offsets count from ``base``, where ``text`` starts in the input as sent: in
    characters, or with ``in_bytes`` in the bytes of its UTF-8 encoding, for text
    the input held as bytes.
    """

    if in_bytes:
        return _read(text, lenient, lambda offset: base + len(text[:offset].encode("utf-8")))
    return _read(text, lenient, lambda offset: base + offset)


def read_bytes(data: bytes, *, lenient: bool = False) -> tuple[Any, list[dict[str, Any]]]:
    """``read`` of UTF-8 ``data``, offsets counted in bytes; raises ``UnicodeDecodeError`` for other bytes."""

    return read(data.decode("utf-8"), lenient=lenient, in_bytes=True)


def _read(text: str, lenient: bool, position: Callable[[int], int]) -> tuple[Any, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    constants: list[tuple[str, str]] = []
    try:
        parsed = json.loads(text, object_pairs_hook=_Members, parse_constant=_Constant)
        value = _resolve(parsed, "$", findings, constants=constants, budget=item_budget.current())
    except (_TooDeep, RecursionError):
        too_deep = _first_too_deep(text)
        if too_deep is None:
            raise
        raise JsonDepthError(too_deep[0], position(too_deep[1])) from None
    located = [(name, path, position(offset)) for (name, path), offset in zip(constants, _constant_offsets(text))]
    if located and not lenient:
        raise JsonConstantError(*located[0])
    findings.extend(_constant_finding(name, path, offset) for name, path, offset in located)
    return value, findings


# What ``read_or_none`` gives for text that is not JSON: ``None`` is JSON's null.
NOT_JSON: Any = object()


def read_or_none(
    text: Any, *, lenient: bool = False, base: int = 0, in_bytes: bool = False
) -> tuple[Any, list[dict[str, Any]]]:
    """``read``, or ``(NOT_JSON, [])`` for text that is not JSON; NaN or Infinity read strictly, or JSON
    nested too deep, still raises."""

    try:
        return read(text, lenient=lenient, base=base, in_bytes=in_bytes)
    except (JsonConstantError, JsonDepthError):
        raise
    except (ValueError, TypeError):
        return NOT_JSON, []


def _constant_offsets(text: str) -> list[int]:
    """Where each NaN, Infinity and -Infinity starts in ``text``, which JSON reads: outside its strings."""

    offsets: list[int] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            index += 1
            while index < len(text) and text[index] != '"':
                index += 2 if text[index] == "\\" else 1
        elif text.startswith(("NaN", "Infinity", "-Infinity"), index):
            offsets.append(index)
            index += len(next(word for word in ("NaN", "Infinity", "-Infinity") if text.startswith(word, index)))
            continue
        index += 1
    return offsets


def _constant_finding(name: str, path: str, offset: int) -> dict[str, Any]:
    return {
        "code": "json-nan-or-infinity",
        "category": "malformed",  # not JSON (RFC 8259), read leniently
        "offset": offset,
        "path": path,
        "message": (
            f"{name} at offset {offset} is not JSON (RFC 8259 has no NaN or Infinity); read leniently, "
            f'it is shown as {{"diagnostic": "{name}"}}'
        ),
    }


def _resolve(
    value: Any,
    path: str,
    findings: list[dict[str, Any]],
    dropped: bool = False,
    *,
    constants: list[tuple[str, str]],
    budget: item_budget.Budget | None,
    depth: int = 0,
) -> Any:
    """``value`` as ``json.loads`` gives it; ``dropped``: it is inside a value the result drops.

    Each NaN or Infinity is noted in ``constants`` with its path, in the order of the text.
    """

    if depth > _MAX_DEPTH:
        raise _TooDeep
    if budget is not None:
        budget.charge(None, path)
    if isinstance(value, _Constant):
        constants.append((str(value), path))
        return {"diagnostic": str(value)}
    if isinstance(value, _Members):
        # The later value wins: the last occurrence of each key is the one kept.
        last = {key: index for index, (key, _member) in enumerate(value)}
        resolved: dict[str, Any] = {}
        occurrences: dict[str, list[Any]] = {}
        for index, (key, member) in enumerate(value):
            member_value = _resolve(
                member,
                _member_path(path, key),
                findings,
                dropped or last[key] != index,
                constants=constants,
                budget=budget,
                depth=depth + 1,
            )
            occurrences.setdefault(key, []).append(member_value)
            resolved[key] = member_value
        for key, values in occurrences.items():
            if len(values) > 1:
                findings.append(_duplicate(_member_path(path, key), key, values, dropped))
        return resolved
    if isinstance(value, list):
        return [
            _resolve(item, f"{path}[{index}]", findings, dropped, constants=constants, budget=budget, depth=depth + 1)
            for index, item in enumerate(value)
        ]
    return value


_BLANK = re.compile(r"[ \t\n\r]*")
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_SCALAR = re.compile(r"[^,\]} \t\n\r]*")


def _first_too_deep(text: str) -> tuple[str, int] | None:
    """The path and offset of the first value nested more than ``_MAX_DEPTH`` deep in JSON ``text``, if any.

    ``text`` is JSON as far as that value: ``json.loads`` read it, or went deeper still.
    """

    found: list[tuple[str, int]] = []

    def skip_value(index: int, path: str, depth: int) -> int:
        # Where the value at ``index`` ends; -1 once the first value too deep is found.
        index = _BLANK.match(text, index).end()
        if depth > _MAX_DEPTH:
            found.append((path, index))
            return -1
        opening = text[index]
        if opening == '"':
            return _STRING.match(text, index).end()
        if opening not in "[{":
            return _SCALAR.match(text, index).end()
        closing = "]" if opening == "[" else "}"
        index = _BLANK.match(text, index + 1).end()
        count = 0
        while text[index] != closing:
            if opening == "{":
                key = _STRING.match(text, index)
                inner = _member_path(path, json.loads(key.group()))
                index = _BLANK.match(text, key.end()).end() + 1
            else:
                inner = f"{path}[{count}]"
            index = skip_value(index, inner, depth + 1)
            if index < 0:
                return index
            index = _BLANK.match(text, index).end()
            if text[index] == ",":
                index = _BLANK.match(text, index + 1).end()
            count += 1
        return index + 1

    skip_value(0, "$", 0)
    return found[0] if found else None


def _member_path(path: str, key: str) -> str:
    return f"{path}{{{json.dumps(key, ensure_ascii=False)}}}"


def _duplicate(path: str, key: str, values: list[Any], inside_dropped: bool) -> dict[str, Any]:
    kept, dropped = values[-1], values[:-1]
    times, which = ("twice", "later") if len(values) == 2 else (f"{len(values)} times", "last")
    spelled = json.dumps(key, ensure_ascii=False)
    if inside_dropped:
        # The object is inside a value the decoded value drops: none of these is in it.
        kept, dropped = None, values
        outcome = f"the decoded value keeps none of them: the object is inside a value it drops ({_all(values)})"
    else:
        outcome = f"the decoded value keeps the {which} value, {_short(kept)}, and drops {_all(dropped)}"
    return {
        "code": "duplicate-json-key",
        "category": "json",
        "offset": None,
        "path": path,
        "key": key,
        "kept": kept,
        "dropped": dropped,
        "message": f"object key {spelled} appears {times}; {outcome}",
    }


def _all(values: list[Any]) -> str:
    return ", ".join(_short(value) for value in values)


def _short(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 40 else f"{text[:37]}..."
