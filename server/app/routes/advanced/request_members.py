"""The members of an Advanced request's ``publicKey`` that must be of one JSON type.

Each check names the first member that is not the type it must be, or a registration
list longer than anything real sends, in a sentence the page shows, before anything reads it.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ...webauthn import client_credentials

# Members each ceremony's publicKey must hold as objects, or as lists, when it has them.
_REGISTRATION_OBJECTS = ("rp", "user", "extensions")
_REGISTRATION_LISTS = ("excludeCredentials", "pubKeyCredParams")
_AUTHENTICATION_OBJECTS = ("extensions",)
_AUTHENTICATION_LISTS = ("allowCredentials",)
# Members of rp and user that must be text when there.
_TEXT_MEMBERS = (("rp", "name"), ("user", "name"), ("user", "displayName"))
# The most algorithms a registration reads: far above the 20 the form offers, so only a
# request sent by hand meets it. Each entry becomes one of fido2's objects.
MAX_ALGORITHM_PARAMS = 256
TOO_MANY_ALGORITHMS = f"pubKeyCredParams lists more than {MAX_ALGORITHM_PARAMS} algorithms. List fewer and try again."
TOO_MANY_EXCLUDED = (
    f"excludeCredentials lists more than {client_credentials.MAX_SENT_CREDENTIALS:,} credentials, "
    "more than a browser keeps. Exclude fewer and try again."
)


def registration_refusal(public_key: Any) -> str | None:
    """Why ``public_key``, or a member registration's begin and complete read, is not the JSON type it
    must be, or is a list longer than they read; else None."""

    if not isinstance(public_key, Mapping):
        return "publicKey must be an object."
    return (
        _shape_refusal(public_key, _REGISTRATION_OBJECTS, _REGISTRATION_LISTS)
        or _text_member_refusal(public_key)
        or _list_length_refusal(public_key)
    )


def authentication_refusal(public_key: Any) -> str | None:
    """Why ``public_key``, or a member authentication's begin reads, is not the JSON type it must be; else None."""

    if not isinstance(public_key, Mapping):
        return "publicKey must be an object."
    refusal = _shape_refusal(public_key, _AUTHENTICATION_OBJECTS, _AUTHENTICATION_LISTS)
    if refusal is None and "rpId" in public_key and not _is_text(public_key["rpId"]):
        return "rpId must be a non-empty string."
    return refusal


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _shape_refusal(public_key: Mapping[str, Any], objects: tuple[str, ...], lists: tuple[str, ...]) -> str | None:
    """Why a member that must be an object, a list or a number of milliseconds is not; else None."""

    for name in objects:
        if name in public_key and not isinstance(public_key[name], Mapping):
            return f"{name} must be an object."
    for name in lists:
        if name in public_key and not isinstance(public_key[name], list):
            return f"{name} must be a list."
    timeout = public_key.get("timeout")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float))):
        return "timeout must be a number of milliseconds."
    return None


def _list_length_refusal(public_key: Mapping[str, Any]) -> str | None:
    """Why excludeCredentials or pubKeyCredParams is longer than a registration reads; else None."""

    if client_credentials.too_many(public_key.get("excludeCredentials")):
        return TOO_MANY_EXCLUDED
    if len(public_key.get("pubKeyCredParams", ())) > MAX_ALGORITHM_PARAMS:
        return TOO_MANY_ALGORITHMS
    return None


def _text_member_refusal(public_key: Mapping[str, Any]) -> str | None:
    """Why rp.id is not a non-empty string, or a name of rp or user no string; else None."""

    rp = public_key.get("rp")
    if isinstance(rp, Mapping) and "id" in rp and not _is_text(rp["id"]):
        return "rp.id must be a non-empty string."
    for parent, name in _TEXT_MEMBERS:
        container = public_key.get(parent)
        if isinstance(container, Mapping) and name in container and not isinstance(container[name], str):
            return f"{parent}.{name} must be a string."
    return None
