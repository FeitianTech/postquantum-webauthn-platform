"""CBOR extended diagnostic notation (EDN): the decoder's lossless view of an item.

``spell`` writes a parsed item as EDN that describes its bytes exactly;
``encode`` reads EDN back to exactly the bytes it notates. A leaf: it imports
nothing from the decoder or encoder packages, so both can use it.
"""
from __future__ import annotations

from .reader import encode
from .spell import spell

__all__ = ["encode", "spell"]
