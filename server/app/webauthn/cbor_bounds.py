"""How deep a ceremony response's CBOR nests and how many items it holds, read before fido2 decodes it.

fido2's CBOR decoder slices the rest of its input for every item it reads and recurses,
with a slice, for every level: a response of empty maps costs time quadratic in its
items, and one nested as deep as Python allows a transient of the response's size per
level. ``walk`` reads only an item's heads, skipping string payloads, with a stack of
counts and no recursion, so its cost is one step a head; a response past
``MAX_DEPTH`` or ``MAX_ITEMS`` is refused before fido2 reads it (``registration_excess``,
``assertion_excess``).

What the walk cannot follow (a truncated head, reserved additional information, a string
longer than what is left) ends it unknown, and fido2 answers for that input as before:
it raises there or, for the string, reads the rest of its input as the string, so it
reads no item after it. Major type 7 is read as fido2 reads it, as its first byte alone
whatever the additional information, since fido2 goes on to read a float's bytes as
items; tags and indefinite lengths, which fido2 refuses at their head, are walked and
counted.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NamedTuple

from fido2.utils import websafe_decode

# Far above any real response: the deepest in the repository's vectors nests 5 levels and
# holds 25 items (a compound attestation), and a compound one of three statements, each with
# two certificates, would nest 6 and hold 46. Bounded by these, fido2's decodes of a 256 KiB
# response cost tens of milliseconds and about 12 MiB, against a second, or 90 MiB, without them.
MAX_DEPTH = 50
MAX_ITEMS = 400

# What a refused response holds too much of.
DEPTH = "depth"
ITEMS = "items"

_FLAG_AT = 0x40
_FLAG_ED = 0x80


class Walk(NamedTuple):
    """Where an item ends (None when the walk could not follow it or stopped past a cap), how
    many levels it nests (a lone value is 1) and how many items it holds, itself included."""

    end: int | None
    depth: int
    items: int


def _head(data: bytes, pos: int) -> tuple[int, int | None, int] | None:
    """The major type, argument (None for an indefinite length) and end of the head at ``pos``."""

    if pos >= len(data):
        return None
    major, info = data[pos] >> 5, data[pos] & 0x1F
    if info < 24:
        return major, info, pos + 1
    if info < 28:
        end = pos + 1 + (1 << (info - 24))
        return None if end > len(data) else (major, int.from_bytes(data[pos + 1 : end], "big"), end)
    return (major, None, pos + 1) if info == 31 else None


def walk(data: bytes, offset: int = 0, *, max_depth: int = MAX_DEPTH, max_items: int = MAX_ITEMS) -> Walk:
    """The extent of the CBOR item at ``offset``, its heads read once; it stops once past a cap."""

    pos, depth, items = offset, 0, 0
    # Each open container's items still to come; -1 for one of indefinite length, closed by a break.
    pending: list[int] = []
    while True:
        if pos >= len(data):
            return Walk(None, depth, items)
        if data[pos] == 0xFF and pending and pending[-1] == -1:
            pending.pop()
            pos += 1
        else:
            items += 1
            depth = max(depth, len(pending) + 1)
            if depth > max_depth or items > max_items:
                return Walk(None, depth, items)
            if data[pos] >> 5 == 7:
                pos += 1
            else:
                head = _head(data, pos)
                if head is None or (head[1] is None and head[0] not in (2, 3, 4, 5)):
                    return Walk(None, depth, items)
                major, argument, pos = head
                if argument is None:
                    pending.append(-1)
                    continue
                if major in (2, 3):
                    if argument > len(data) - pos:
                        return Walk(None, depth, items)
                    pos += argument
                elif major == 6:
                    pending.append(1)
                    continue
                elif major in (4, 5) and argument:
                    pending.append(argument * 2 if major == 5 else argument)
                    continue
        # The item is complete: count it against the containers it completes.
        while pending and pending[-1] != -1:
            pending[-1] -= 1
            if pending[-1]:
                break
            pending.pop()
        if not pending:
            return Walk(pos, depth, items)


def _excess(extent: Walk) -> str | None:
    if extent.depth > MAX_DEPTH:
        return DEPTH
    return ITEMS if extent.items > MAX_ITEMS else None


def _wire_bytes(response: Any, member: str) -> bytes | None:
    """A member of the response's ``response`` as fido2 reads it into bytes: base64url text
    (as fido2's lenient ``websafe_decode`` reads it) or a list of byte values."""

    inner = response.get("response") if isinstance(response, Mapping) else None
    value = inner.get(member) if isinstance(inner, Mapping) else None
    try:
        if isinstance(value, str):
            return websafe_decode(value)
        if isinstance(value, list):
            return bytes(value)
    except (ValueError, TypeError):
        pass
    return None


def _auth_data_excess(auth_data: bytes) -> str | None:
    """What the authenticator data's CBOR (its credential key, its extensions) holds too much of."""

    if len(auth_data) < 37:
        return None
    pos = 37
    if auth_data[32] & _FLAG_AT:
        if len(auth_data) < 55:
            return None
        pos = 55 + int.from_bytes(auth_data[53:55], "big")
        key = walk(auth_data, pos)
        if key.end is None:
            return _excess(key)
        pos = key.end
    return _excess(walk(auth_data, pos)) if auth_data[32] & _FLAG_ED else None


def _auth_data_of(attestation_object: bytes) -> bytes | None:
    """The authData byte string of an attestation object, the last one its map holds, as fido2's
    decode keeps it; cut at the end of the object when its length passes it, as fido2 cuts it."""

    head = _head(attestation_object, 0)
    if head is None or head[0] != 5 or head[1] is None:
        return None
    found = None
    pos = head[2]
    for _ in range(head[1]):
        key, key_end = _head(attestation_object, pos), walk(attestation_object, pos).end
        if key is None or key_end is None:
            break
        if key[0] == 3 and attestation_object[key[2] : key_end] == b"authData":
            value = _head(attestation_object, key_end)
            found = None
            if value is not None and value[0] == 2 and value[1] is not None:
                found = attestation_object[value[2] : value[2] + value[1]]
        value_end = walk(attestation_object, key_end).end
        if value_end is None:
            break
        pos = value_end
    return found


def registration_excess(response: Any) -> str | None:
    """What a registration response's attestation object, or the authenticator data inside it,
    holds too much of (``DEPTH`` or ``ITEMS``); None when neither does or it is not read here."""

    attestation_object = _wire_bytes(response, "attestationObject")
    if attestation_object is None:
        return None
    excess = _excess(walk(attestation_object))
    if excess is not None:
        return excess
    auth_data = _auth_data_of(attestation_object)
    return None if auth_data is None else _auth_data_excess(auth_data)


def assertion_excess(response: Any) -> str | None:
    """What an assertion's authenticator data holds too much of, as ``registration_excess``."""

    auth_data = _wire_bytes(response, "authenticatorData")
    return None if auth_data is None else _auth_data_excess(auth_data)
