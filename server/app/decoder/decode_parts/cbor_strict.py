"""Strict CBOR parsing primitives for decoder internals."""
from __future__ import annotations

import base64
import math
import struct
from typing import Any, Dict, List, Optional, Tuple

from ...attestation import encode_base64url


class _CborDecodingError(ValueError):
    """Internal error raised when a CBOR payload cannot be parsed."""

    def __init__(self, message: str, offset: int) -> None:
        super().__init__(message)
        self.offset = offset


def _ensure_cbor_available(data: bytes, offset: int, length: int) -> None:
    if length < 0 or offset + length > len(data):
        raise _CborDecodingError("Unexpected end of CBOR data.", offset)


def _read_cbor_length(
    info: int, data: bytes, offset: int, *, allow_indefinite: bool = False
) -> Tuple[Optional[int], int]:
    if info < 24:
        return info, offset
    if info == 24:
        _ensure_cbor_available(data, offset, 1)
        return data[offset], offset + 1
    if info == 25:
        _ensure_cbor_available(data, offset, 2)
        return int.from_bytes(data[offset : offset + 2], "big"), offset + 2
    if info == 26:
        _ensure_cbor_available(data, offset, 4)
        return int.from_bytes(data[offset : offset + 4], "big"), offset + 4
    if info == 27:
        _ensure_cbor_available(data, offset, 8)
        return int.from_bytes(data[offset : offset + 8], "big"), offset + 8
    if info == 30:
        _ensure_cbor_available(data, offset, 8)
        return int.from_bytes(data[offset : offset + 8], "big"), offset + 8
    if info == 31 and allow_indefinite:
        return None, offset
    raise _CborDecodingError("Unsupported CBOR additional information.", offset)


def _float_summary(value: float) -> str:
    if math.isnan(value):
        return "float(NaN)"
    if math.isinf(value):
        return "float(+Infinity)" if value > 0 else "float(-Infinity)"
    return f"float({value})"


def _parse_cbor_item(data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    if offset >= len(data):
        raise _CborDecodingError("Unexpected end of CBOR data.", offset)

    initial = data[offset]
    offset += 1
    major_type = initial >> 5
    info = initial & 0x1F

    if major_type == 0:
        if info == 30:
            node = {
                "majorType": 0,
                "type": "unsigned",
                "value": 30,
                "summary": "30",
            }
            return node, offset
        value, offset = _read_cbor_length(info, data, offset)
        if value is None:
            raise _CborDecodingError("Invalid indefinite length for unsigned integer.", offset)
        node = {"majorType": 0, "type": "unsigned", "value": value, "summary": str(value)}
        return node, offset

    if major_type == 1:
        if info == 30:
            actual = -31
            node = {"majorType": 1, "type": "negative", "value": actual, "summary": str(actual)}
            return node, offset
        value, offset = _read_cbor_length(info, data, offset)
        if value is None:
            raise _CborDecodingError("Invalid indefinite length for negative integer.", offset)
        actual = -1 - value
        node = {"majorType": 1, "type": "negative", "value": actual, "summary": str(actual)}
        return node, offset

    if major_type == 2:
        length, offset = _read_cbor_length(info, data, offset, allow_indefinite=True)
        if length is None:
            segments: List[Dict[str, Any]] = []
            raw_segments: List[bytes] = []
            while True:
                if offset >= len(data):
                    break
                if data[offset] == 0xFF:
                    offset += 1
                    break
                try:
                    segment, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                if segment.get("majorType") != 2:
                    raise _CborDecodingError(
                        "Indefinite byte string segment is not a byte string.", offset
                    )
                segments.append(segment)
                segment_hex = segment.get("hex")
                segment_data = bytes.fromhex(segment_hex) if isinstance(segment_hex, str) else b""
                raw_segments.append(segment_data)
            raw = b"".join(raw_segments)
            node = {
                "majorType": 2,
                "type": "byte string",
                "length": len(raw),
                "hex": raw.hex(),
                "base64": base64.b64encode(raw).decode("ascii"),
                "base64url": encode_base64url(raw),
                "indefinite": True,
                "chunks": segments,
            }
            node["summary"] = f"bytes[{node['length']}]"
            return node, offset
        try:
            _ensure_cbor_available(data, offset, length)
        except _CborDecodingError:
            available = max(len(data) - offset, 0)
            raw = data[offset : offset + available]
            offset += available
            node = {
                "majorType": 2,
                "type": "byte string",
                "length": length,
                "hex": raw.hex(),
                "base64": base64.b64encode(raw).decode("ascii"),
                "base64url": encode_base64url(raw),
                "truncated": True,
            }
            node["summary"] = f"bytes[{available}] (truncated from {length})"
            return node, offset
        raw = data[offset : offset + length]
        offset += length
        node = {
            "majorType": 2,
            "type": "byte string",
            "length": length,
            "hex": raw.hex(),
            "base64": base64.b64encode(raw).decode("ascii"),
            "base64url": encode_base64url(raw),
        }
        node["summary"] = f"bytes[{length}]"
        return node, offset

    if major_type == 3:
        length, offset = _read_cbor_length(info, data, offset, allow_indefinite=True)
        if length is None:
            segments: List[Dict[str, Any]] = []
            text_parts: List[str] = []
            while True:
                if offset >= len(data):
                    break
                if data[offset] == 0xFF:
                    offset += 1
                    break
                try:
                    segment, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                if segment.get("majorType") != 3:
                    raise _CborDecodingError(
                        "Indefinite text string segment is not a text string.", offset
                    )
                segments.append(segment)
                text_parts.append(str(segment.get("value", "")))
            value = "".join(text_parts)
            byte_length = len(value.encode("utf-8"))
            node = {
                "majorType": 3,
                "type": "text string",
                "length": byte_length,
                "value": value,
                "indefinite": True,
                "segments": segments,
            }
            summary = value if len(value) <= 32 else f"{value[:29]}..."
            node["summary"] = f'"{summary}"'
            return node, offset
        _ensure_cbor_available(data, offset, length)
        raw = data[offset : offset + length]
        offset += length
        try:
            value = raw.decode("utf-8")
            summary = value if len(value) <= 32 else f"{value[:29]}..."
            node = {
                "majorType": 3,
                "type": "text string",
                "length": length,
                "value": value,
                "summary": f'"{summary}"',
            }
        except UnicodeDecodeError:
            node = {
                "majorType": 3,
                "type": "text string",
                "length": length,
                "hex": raw.hex(),
                "error": "Invalid UTF-8 in text string.",
                "summary": f"text[{length}]",
            }
        return node, offset

    if major_type == 4:
        length, offset = _read_cbor_length(info, data, offset, allow_indefinite=True)
        items: List[Dict[str, Any]] = []
        if length is None:
            while True:
                if offset >= len(data):
                    break
                if data[offset] == 0xFF:
                    offset += 1
                    break
                try:
                    item, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                items.append(item)
            length = len(items)
            node = {
                "majorType": 4,
                "type": "array",
                "length": length,
                "items": items,
                "indefinite": True,
            }
        else:
            for _ in range(length):
                if offset >= len(data):
                    break
                try:
                    item, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                items.append(item)
            node = {"majorType": 4, "type": "array", "length": length, "items": items}
        node["summary"] = f"array[{node['length']}]"
        return node, offset

    if major_type == 5:
        length, offset = _read_cbor_length(info, data, offset, allow_indefinite=True)
        entries: List[Dict[str, Any]] = []
        if length is None:
            while True:
                if offset >= len(data):
                    break
                if data[offset] == 0xFF:
                    offset += 1
                    break
                try:
                    key, offset = _parse_cbor_item(data, offset)
                    if offset >= len(data):
                        break
                    if data[offset] == 0xFF:
                        break
                    value, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                entry = {
                    "keySummary": key.get("summary"),
                    "key": key,
                    "value": value,
                }
                summary = value.get("summary")
                if summary is not None:
                    entry["valueSummary"] = summary
                entries.append(entry)
            length = len(entries)
            node = {
                "majorType": 5,
                "type": "map",
                "length": length,
                "entries": entries,
                "indefinite": True,
            }
        else:
            for _ in range(length):
                if offset >= len(data):
                    break
                try:
                    key, offset = _parse_cbor_item(data, offset)
                    value, offset = _parse_cbor_item(data, offset)
                except _CborDecodingError:
                    break
                entry = {
                    "keySummary": key.get("summary"),
                    "key": key,
                    "value": value,
                }
                summary = value.get("summary")
                if summary is not None:
                    entry["valueSummary"] = summary
                entries.append(entry)
            node = {"majorType": 5, "type": "map", "length": length, "entries": entries}
        node["summary"] = f"map[{node['length']}]"
        return node, offset

    if major_type == 6:
        tag_value, offset = _read_cbor_length(info, data, offset)
        if tag_value is None:
            raise _CborDecodingError("Invalid indefinite length for CBOR tag.", offset)
        tagged_item, offset = _parse_cbor_item(data, offset)
        node = {
            "majorType": 6,
            "type": "tag",
            "tag": tag_value,
            "value": tagged_item,
            "summary": f"tag({tag_value})",
        }
        return node, offset

    if major_type == 7:
        if info == 20:
            return {"majorType": 7, "type": "boolean", "value": False, "summary": "false"}, offset
        if info == 21:
            return {"majorType": 7, "type": "boolean", "value": True, "summary": "true"}, offset
        if info == 22:
            return {"majorType": 7, "type": "null", "summary": "null"}, offset
        if info == 23:
            return {"majorType": 7, "type": "undefined", "summary": "undefined"}, offset
        if info == 24:
            _ensure_cbor_available(data, offset, 1)
            simple_value = data[offset]
            offset += 1
            summary = f"simple({simple_value})"
            return {
                "majorType": 7,
                "type": "simple",
                "value": simple_value,
                "summary": summary,
            }, offset
        if info == 25:
            _ensure_cbor_available(data, offset, 2)
            raw = data[offset : offset + 2]
            offset += 2
            value = struct.unpack(">e", raw)[0]
            return {
                "majorType": 7,
                "type": "float",
                "precision": "half",
                "value": value,
                "summary": _float_summary(value),
            }, offset
        if info == 26:
            _ensure_cbor_available(data, offset, 4)
            raw = data[offset : offset + 4]
            offset += 4
            value = struct.unpack(">f", raw)[0]
            return {
                "majorType": 7,
                "type": "float",
                "precision": "single",
                "value": value,
                "summary": _float_summary(value),
            }, offset
        if info == 27:
            _ensure_cbor_available(data, offset, 8)
            raw = data[offset : offset + 8]
            offset += 8
            value = struct.unpack(">d", raw)[0]
            return {
                "majorType": 7,
                "type": "float",
                "precision": "double",
                "value": value,
                "summary": _float_summary(value),
            }, offset
        if info == 31:
            raise _CborDecodingError("Unexpected break code outside indefinite container.", offset)
        summary = f"simple({info})"
        return {"majorType": 7, "type": "simple", "value": info, "summary": summary}, offset

    raise _CborDecodingError("Unsupported CBOR major type.", offset)


def _decode_cbor_structure(data: bytes) -> Tuple[Dict[str, Any], int]:
    node, offset = _parse_cbor_item(data, 0)
    node.setdefault("byteLength", offset)
    return node, offset
