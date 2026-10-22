"""The members of an Advanced request's ``publicKey`` that must be of one JSON type.

Each check names the first member that is not the type it must be, in a sentence
the page shows, before anything reads it.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# Members a registration request's publicKey must hold as objects, or as a
# list, when it has them.
_OBJECT_MEMBERS = ("rp", "user", "extensions")
_LIST_MEMBERS = ("excludeCredentials",)
# Members of rp and user that must be text when there.
_TEXT_MEMBERS = (("rp", "name"), ("user", "name"), ("user", "displayName"))


def registration_refusal(public_key: Any) -> str | None:
    """Why ``public_key``, or a member registration's begin and complete read, is not the JSON type it must be; else None."""

    if not isinstance(public_key, Mapping):
        return "publicKey must be an object."
    for name in _OBJECT_MEMBERS:
        if name in public_key and not isinstance(public_key[name], Mapping):
            return f"{name} must be an object."
    for name in _LIST_MEMBERS:
        if name in public_key and not isinstance(public_key[name], list):
            return f"{name} must be a list."
    timeout = public_key.get("timeout")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float))):
        return "timeout must be a number of milliseconds."
    return _text_member_refusal(public_key)


def _text_member_refusal(public_key: Mapping[str, Any]) -> str | None:
    """Why rp.id is not a non-empty string, or a name of rp or user no string; else None."""

    rp = public_key.get("rp")
    if isinstance(rp, Mapping) and "id" in rp and not (isinstance(rp["id"], str) and rp["id"]):
        return "rp.id must be a non-empty string."
    for parent, name in _TEXT_MEMBERS:
        container = public_key.get(parent)
        if isinstance(container, Mapping) and name in container and not isinstance(container[name], str):
            return f"{parent}.{name} must be a string."
    return None
