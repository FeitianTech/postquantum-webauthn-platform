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
deeper than about a dozen.

A JSON body holding more than 100,000 values is refused before it is parsed too
(``TooManyValues``, 400 in JSON): Python's reader keeps about 26 bytes for each
byte of ``{},``, 210 MiB for an 8 MiB body. Its strings set aside, a body holds at
most one value more than its commas and opening brackets, and that is what is
counted. The page's largest body, an Advanced sign-in sending every saved
credential, holds 14 values for each one: about 20,000 for as many as a browser's
storage keeps. ``check_limits`` asks both, for every route and the CSP report; the
metadata upload, which reads its own JSON, asks it with a cap of its own.

The body is scanned as the reader reads bytes: in the UTF-8, UTF-16 or UTF-32
its first bytes name (``json.detect_encoding``). Read byte by byte, UTF-16 or
UTF-32 text can hold a quote's byte where there is no quote, and hide brackets
inside what looks like a string.

A request's JSON is RFC 8259's: ``NaN``, ``Infinity`` and ``-Infinity``, which
Python's reader takes, are refused (``NotStrictJson``, 400 in JSON), as the codec
refuses them; so is a number too large for a double (``1e400``), which it would read
as Infinity. Every route reads its body here (``json_object``), and the CSP report
through ``loads``; not ``request.get_json``, whose reader (``app.json``, which Flask
gives each request) takes them. The app's own answers are read back as written.

A body of more than ``LARGE_BODY_BYTES`` costs many times its size to check, parse and
answer, so a process works on two at a time: once its bytes are read, such a body takes
one of two places, kept until the request ends (``give_back_place``, a teardown). One that
finds no place within 2 seconds is refused (``LargeBodiesBusy``, 503 with ``Retry-After``).
The place is taken after the read, so a client sending slowly holds none.
"""
from __future__ import annotations

import itertools
import json
import math
import operator
import re
import threading
from typing import Any

from flask import json as flask_json
from flask import request
from werkzeug.exceptions import BadRequest, ServiceUnavailable

MAX_DEPTH = 64
MAX_VALUES = 100_000

# Larger bodies cost far more than their size while read: 8 MiB of 4-byte characters about 74 MiB,
# a 1 MiB Codec text of control characters about 50 MB to answer. 256 KiB takes in a Codec request
# near its limit; a sign-in sending a few hundred saved credentials passes it too.
LARGE_BODY_BYTES = 256 * 1024
# Two such bodies at a time in a process, of 16 threads in 1 GiB; the others' bytes wait.
_LARGE_BODIES = threading.BoundedSemaphore(2)
# A large body waits this long for a place, then is told to try again.
_WAIT_SECONDS = 2
RETRY_AFTER_SECONDS = 5
# In the request's environ while it holds a place: taken once, however often the body is read.
_PLACE = "pqc.large_body_place"

# A string to its closing quote, or to the body's end when none closes it: Python's reader reads no further.
# So a match never fails, and the search never starts again inside text it took; nor does a possessive
# repeat (*+) go back, so it keeps no state for each escape. The scan is linear in the body's length.
_STRING = re.compile(rb'"[^"\\]*+(?:\\.[^"\\]*+)*+"?', re.DOTALL)
# re.sub keeps what it leaves around each string until it joins it all, about 170 bytes a string: 476 MB for
# 8 MiB of short strings. So it is given a stretch of the body at a time, up to 4,096 strings and the text
# between them; a stretch ends where a string does, or before one.
_STRETCH = re.compile(rb'(?:[^"]++|' + _STRING.pattern + rb"){1,4096}+", re.DOTALL)
# Each bracket left once the strings are set aside, as a step: 2 for an opening one, 0 for a closing one.
_STEPS = bytes.maketrans(b"[{]}", b"\x02\x02\x00\x00")
_NOT_BRACKETS = bytes(byte for byte in range(256) if byte not in b"[]{}")


class NestedTooDeep(BadRequest):
    """A JSON body nested more than ``MAX_DEPTH`` deep, refused before it is parsed."""


class TooManyValues(BadRequest):
    """A JSON body holding more than ``MAX_VALUES`` values, refused before it is parsed."""


class LargeBodiesBusy(ServiceUnavailable):
    """A body over ``LARGE_BODY_BYTES`` that found no place while others were read."""


class NotStrictJson(BadRequest):
    """A JSON request body holding ``NaN``, ``Infinity``, ``-Infinity`` or a number no double
    holds: not a ValueError, so a reader's ``except ValueError`` (malformed JSON, read as no
    body) lets it through."""

    def __init__(self, text: str, sentence: str) -> None:
        super().__init__()
        self.text = text
        self.sentence = sentence


def _refuse_constant(constant: str) -> Any:
    raise NotStrictJson(constant, f"The request body holds {constant}, which is not JSON: RFC 8259 has no NaN or Infinity.")


def _finite(text: str) -> float:
    number = float(text)
    if not math.isfinite(number):
        raise NotStrictJson(text[:32], f"The request body holds {text[:32]}, a number too large to read.")
    return number


def loads(data: str | bytes, **kwargs: Any) -> Any:
    """``data`` read as Flask reads JSON, refusing what Python's reader would read as NaN or
    Infinity (``NotStrictJson``)."""

    return flask_json.loads(data, parse_constant=_refuse_constant, parse_float=_finite, **kwargs)



def _as_utf8(data: bytes) -> bytes | None:
    """JSON ``data`` in UTF-8, as the reader decodes it; None when it cannot (it reads nothing then)."""

    encoding = json.detect_encoding(data)
    if encoding.startswith(("utf-16", "utf-32")):
        try:
            # Decoded as json.loads decodes it. In UTF-8 each bracket, quote and backslash is its one ASCII byte.
            return data.decode(encoding, "surrogatepass").encode("utf-8", "surrogatepass")
        except UnicodeDecodeError:
            return None
    return data


def _outside_strings(data: bytes) -> bytes:
    return b"".join(_STRING.sub(b"", stretch) for stretch in _STRETCH.findall(data))


def _too_deep(outside: bytes) -> bool:
    steps = outside.translate(_STEPS, _NOT_BRACKETS)
    # After k brackets, twice the opening ones less k is how deep the text is there.
    depths = map(operator.sub, itertools.accumulate(steps), itertools.count(1))
    return any(map(MAX_DEPTH.__lt__, depths))


def _openings(data: bytes) -> int:
    return data.count(b"[") + data.count(b"{")


def nested_too_deep(data: bytes) -> bool:
    """Whether JSON ``data`` nests arrays and objects more than ``MAX_DEPTH`` deep, its strings set aside."""

    data = _as_utf8(data)
    if data is None or _openings(data) <= MAX_DEPTH:
        return False
    return _too_deep(_outside_strings(data))


def check_limits(data: bytes, max_values: int = MAX_VALUES) -> int:
    """Refuse JSON ``data`` nested more than ``MAX_DEPTH`` deep (``NestedTooDeep``) or holding
    more than ``max_values`` values (``TooManyValues``), its strings set aside, before it is parsed.

    Gives the count it compared otherwise: its opening brackets and commas, those in its strings
    too unless it holds many."""

    data = _as_utf8(data)
    if data is None:
        return 0
    openings = _openings(data)
    values = openings + data.count(b",")
    # Counted with its strings in, most bodies are within both limits: nothing more to do.
    if openings <= MAX_DEPTH and values < max_values:
        return values
    outside = _outside_strings(data)
    if _too_deep(outside):
        raise NestedTooDeep()
    values = _openings(outside) + outside.count(b",")
    if values >= max_values:
        raise TooManyValues()
    return values


def json_object() -> dict[str, Any]:
    """The request's JSON body when it is an object; an empty object for any other body,
    malformed JSON or none."""

    if not request.is_json:
        return {}
    data = request.get_data(cache=True)
    _take_place(data)
    check_limits(data)
    try:
        body = loads(data)
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _take_place(data: bytes) -> None:
    if len(data) <= LARGE_BODY_BYTES or request.environ.get(_PLACE):
        return
    if not _LARGE_BODIES.acquire(timeout=_WAIT_SECONDS):
        raise LargeBodiesBusy()
    request.environ[_PLACE] = True


def give_back_place(_error: BaseException | None = None) -> None:
    """Give back the request's place, if it holds one, once it has been answered or failed."""

    if request.environ.pop(_PLACE, False):
        _LARGE_BODIES.release()


def init_app(app) -> None:
    app.teardown_request(give_back_place)
