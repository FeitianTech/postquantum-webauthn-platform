"""Compatibility facade for CBOR parser internals.

This module preserves monkeypatchable symbols expected by decode.py tests while
forwarding strict/lenient logic into smaller split modules.
"""
from __future__ import annotations

from typing import Any, Dict, Mapping, Tuple

from . import cbor_lenient as _lenient
from . import cbor_strict as _strict

_CborDecodingError = _strict._CborDecodingError
_ensure_cbor_available = _strict._ensure_cbor_available
_float_summary = _strict._float_summary
_read_cbor_length = _strict._read_cbor_length


def _parse_cbor_item(data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    original_read_cbor_length = _strict._read_cbor_length
    original_ensure_cbor_available = _strict._ensure_cbor_available
    original_float_summary = _strict._float_summary
    try:
        _strict._read_cbor_length = _read_cbor_length
        _strict._ensure_cbor_available = _ensure_cbor_available
        _strict._float_summary = _float_summary
        return _strict._parse_cbor_item(data, offset)
    finally:
        _strict._read_cbor_length = original_read_cbor_length
        _strict._ensure_cbor_available = original_ensure_cbor_available
        _strict._float_summary = original_float_summary


def _decode_cbor_structure(data: bytes) -> Tuple[Dict[str, Any], int]:
    node, offset = _parse_cbor_item(data, 0)
    node.setdefault("byteLength", offset)
    return node, offset


def _structure_to_value(node: Mapping[str, Any]) -> Any:
    return _lenient._structure_to_value(node)


def _lenient_read_uint(info: int, data: bytes, offset: int) -> Tuple[int, int]:
    return _lenient._lenient_read_uint(info, data, offset)


def _lenient_decode_from(data: bytes, offset: int = 0) -> Tuple[Any, int]:
    return _lenient._lenient_decode_from(data, offset)
