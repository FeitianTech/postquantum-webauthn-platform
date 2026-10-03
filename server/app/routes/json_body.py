"""The JSON body an API route reads: an object, or an empty one.

``request.get_json`` gives whatever JSON a body holds -- a list, a string, a
number -- or None when it holds none. Every route reads named members of an
object, so anything else is read as an object without members, and the route
answers what it answers for a missing member.
"""
from __future__ import annotations

from typing import Any

from flask import request


def json_object() -> dict[str, Any]:
    """The request's JSON body when it is an object; an empty object for any other body."""

    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}
