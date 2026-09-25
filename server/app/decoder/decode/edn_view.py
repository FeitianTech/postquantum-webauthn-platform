"""The item the decoder read, in extended diagnostic notation: ``data.edn``.

Beside the decoded value, never in place of it. ``decodedValue`` is JSON, so it
cannot tell an integer key from a text key, bytes from text, or show a head's
width, a chunked string, a float's width or a duplicated key; the EDN text does,
exactly: the encoder's EDN input turns it back into the same bytes. It is given
only when it does -- the text is read back and compared with the item's bytes --
so a tree the lenient parser could not read whole gets no EDN rather than a
wrong one.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .. import edn


def extra(node: Mapping[str, Any], data: bytes) -> dict[str, str]:
    """``{"edn": text}`` for the item ``node`` parsed from ``data``, or nothing when no exact text exists."""

    try:
        text = edn.spell(node)
        exact = edn.encode(text) == data[node["offset"] : node["end"]]
    except (KeyError, TypeError, ValueError):
        return {}
    return {"edn": text} if exact else {}
