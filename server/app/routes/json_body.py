"""The JSON body an API route reads: an object, or an empty one.

``request.get_json`` gives whatever JSON a body holds -- a list, a string, a
number -- or None when it holds none. Every route reads named members of an
object, so anything else is read as an object without members, and the route
answers what it answers for a missing member.

A JSON body nested more than 64 deep, as deep as the decoder reads, is refused
before it is parsed (``NestedTooDeep``, answered 400 in JSON by
``routes/errors.py``). Python's JSON reader goes as deep as the text does until
its stack runs out, about 10,000 levels on Python 3.12, and any walk over a value
deeper than about 1,000 levels fails the same way; no body the page sends nests
deeper than about a dozen. The CSP report route and the metadata upload, which
read their own JSON, ask ``nested_too_deep`` too.
"""
from __future__ import annotations

import itertools
import operator
import re
from typing import Any

from flask import request
from werkzeug.exceptions import BadRequest

MAX_DEPTH = 64

# A string to its closing quote, or to the body's end when none closes it: Python's reader reads no further.
# So a match never fails, and the search never starts again inside text it took; nor does a possessive
# repeat (*+) go back, so it keeps no state for each escape. The scan is linear in the body's length.
_STRING = re.compile(rb'"[^"\\]*+(?:\\.[^"\\]*+)*+"?', re.DOTALL)
# Each bracket left once the strings are set aside, as a step: 2 for an opening one, 0 for a closing one.
_STEPS = bytes.maketrans(b"[{]}", b"\x02\x02\x00\x00")
_NOT_BRACKETS = bytes(byte for byte in range(256) if byte not in b"[]{}")


class NestedTooDeep(BadRequest):
    """A JSON body nested more than ``MAX_DEPTH`` deep, refused before it is parsed."""


def nested_too_deep(data: bytes) -> bool:
    """Whether JSON ``data`` nests arrays and objects more than ``MAX_DEPTH`` deep, its strings set aside."""

    if data.count(b"[") + data.count(b"{") <= MAX_DEPTH:
        return False
    steps = _STRING.sub(b"", data).translate(_STEPS, _NOT_BRACKETS)
    # After k brackets, twice the opening ones less k is how deep the text is there.
    depths = map(operator.sub, itertools.accumulate(steps), itertools.count(1))
    return any(map(MAX_DEPTH.__lt__, depths))


def json_object() -> dict[str, Any]:
    """The request's JSON body when it is an object; an empty object for any other body."""

    if request.is_json and nested_too_deep(request.get_data(cache=True)):
        raise NestedTooDeep()
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}
