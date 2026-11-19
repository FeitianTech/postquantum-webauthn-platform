"""Maps whose only key holds a map, level after level, and the memory checking one takes."""
from __future__ import annotations

import tracemalloc
from collections.abc import Callable
from typing import Any

from server.app.decoder.decode import cbor_parser


def key_chain(maps: int, levels: int) -> tuple[dict[str, Any], bytes]:
    """An array of ``maps`` maps {0: 0}, then ``levels`` times the only key of a map {key: 0}: its node and bytes."""

    item = bytes([0x99]) + maps.to_bytes(2, "big") + bytes([0xA1, 0x00, 0x00]) * maps
    for _ in range(levels):
        item = bytes([0xA1]) + item + bytes([0x00])
    node, _end, _skipped = cbor_parser.decode_item(item)
    return node, item


def traced_peak(check: Callable[[], Any]) -> int:
    """The most memory ``check`` held at once, in bytes."""

    tracemalloc.start()
    try:
        check()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak
