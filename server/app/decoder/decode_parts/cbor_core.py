"""Compatibility facade for CBOR parser internals.

Nothing in the decoder routes through this module any more: each caller reaches
``cbor_strict`` or ``cbor_lenient`` directly, so a patch applied to the module
that defines a helper is the one the parser reads. The delegates below resolve
their target at call time for the same reason -- a plain assignment here would
bind at import and stop seeing such a patch.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import cbor_lenient as _lenient
from . import cbor_strict as _strict


def _parse_cbor_item(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    return _strict._parse_cbor_item(data, offset)


def _decode_cbor_structure(data: bytes) -> tuple[dict[str, Any], int]:
    return _strict._decode_cbor_structure(data)


def _structure_to_value(node: Mapping[str, Any]) -> Any:
    return _lenient._structure_to_value(node)


def _lenient_read_uint(info: int, data: bytes, offset: int) -> tuple[int, int]:
    return _lenient._lenient_read_uint(info, data, offset)


def _lenient_decode_from(data: bytes, offset: int = 0) -> tuple[Any, int]:
    return _lenient._lenient_decode_from(data, offset)
