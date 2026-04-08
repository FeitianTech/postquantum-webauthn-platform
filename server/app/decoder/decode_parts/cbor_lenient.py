"""Lenient CBOR decoding and structure-value conversion helpers."""
from __future__ import annotations

import struct
from typing import Any, Dict, List, Mapping, Sequence, Tuple


def _structure_to_value(node: Mapping[str, Any]) -> Any:
    major_type = node.get("majorType")
    node_type = node.get("type")

    if major_type in (0, 1, 7):
        if node_type == "null":
            return None
        if node_type == "undefined":
            return None
        if node_type == "boolean":
            return bool(node.get("value"))
        return node.get("value")

    if major_type == 2:
        hex_value = node.get("hex")
        if isinstance(hex_value, str):
            try:
                return bytes.fromhex(hex_value)
            except ValueError:
                return b""
        chunks = node.get("chunks")
        if isinstance(chunks, Sequence):
            return b"".join(
                bytes(_structure_to_value(chunk) or b"")  # type: ignore[arg-type]
                for chunk in chunks
            )
        return b""

    if major_type == 3:
        text_value = node.get("value")
        if isinstance(text_value, str):
            return text_value
        return ""

    if major_type == 4:
        items = node.get("items")
        if not isinstance(items, Sequence):
            return []
        return [_structure_to_value(item) for item in items]

    if major_type == 5:
        entries = node.get("entries")
        if not isinstance(entries, Sequence):
            return {}
        result: Dict[Any, Any] = {}
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            key_node = entry.get("key")
            value_node = entry.get("value")
            key = _structure_to_value(key_node) if isinstance(key_node, Mapping) else None
            value = (
                _structure_to_value(value_node)
                if isinstance(value_node, Mapping)
                else value_node
            )
            if key is None:
                continue
            try:
                result[key] = value
            except TypeError:
                result[str(key)] = value
        return result

    if major_type == 6:
        tagged_value = node.get("value")
        converted = (
            _structure_to_value(tagged_value)
            if isinstance(tagged_value, Mapping)
            else tagged_value
        )
        return {"tag": node.get("tag"), "value": converted}

    return node.get("value")


def _lenient_read_uint(info: int, data: bytes, offset: int) -> Tuple[int, int]:
    if info <= 23:
        return info, offset
    if info == 24:
        if offset >= len(data):
            return 0, offset
        return data[offset], offset + 1
    if info == 25:
        if offset + 2 > len(data):
            return 0, len(data)
        return int.from_bytes(data[offset : offset + 2], "big"), offset + 2
    if info == 26:
        if offset + 4 > len(data):
            return 0, len(data)
        return int.from_bytes(data[offset : offset + 4], "big"), offset + 4
    if info == 27:
        if offset + 8 > len(data):
            return 0, len(data)
        return int.from_bytes(data[offset : offset + 8], "big"), offset + 8
    if info in {28, 29, 30}:
        return info, offset
    return 0, offset


def _lenient_decode_from(data: bytes, offset: int = 0) -> Tuple[Any, int]:
    if offset >= len(data):
        return None, len(data)

    initial = data[offset]
    offset += 1
    major_type = initial >> 5
    info = initial & 0x1F

    if major_type == 0:
        value, offset = _lenient_read_uint(info, data, offset)
        return value, offset

    if major_type == 1:
        value, offset = _lenient_read_uint(info, data, offset)
        return -1 - value, offset

    if major_type == 2:
        if info == 31:
            chunks: List[bytes] = []
            while offset < len(data):
                if data[offset] == 0xFF:
                    offset += 1
                    break
                chunk, offset = _lenient_decode_from(data, offset)
                if isinstance(chunk, bytes):
                    chunks.append(chunk)
                else:
                    break
            return b"".join(chunks), offset
        length, offset = _lenient_read_uint(info, data, offset)
        length = min(length, len(data) - offset)
        raw = data[offset : offset + length]
        offset += length
        return raw, offset

    if major_type == 3:
        if info == 31:
            parts: List[str] = []
            while offset < len(data):
                if data[offset] == 0xFF:
                    offset += 1
                    break
                segment, offset = _lenient_decode_from(data, offset)
                if isinstance(segment, str):
                    parts.append(segment)
            return "".join(parts), offset
        length, offset = _lenient_read_uint(info, data, offset)
        length = min(length, len(data) - offset)
        raw = data[offset : offset + length]
        offset += length
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            value = raw.decode("utf-8", errors="replace")
        return value, offset

    if major_type == 4:
        items: List[Any] = []
        if info == 31:
            while offset < len(data):
                if data[offset] == 0xFF:
                    offset += 1
                    break
                item, offset = _lenient_decode_from(data, offset)
                if item is None and offset >= len(data):
                    break
                items.append(item)
            return items, offset
        length, offset = _lenient_read_uint(info, data, offset)
        for _ in range(length):
            if offset >= len(data):
                break
            item, offset = _lenient_decode_from(data, offset)
            if item is None and offset >= len(data):
                break
            items.append(item)
        return items, offset

    if major_type == 5:
        mapping: Dict[Any, Any] = {}
        if info == 31:
            while offset < len(data):
                if data[offset] == 0xFF:
                    offset += 1
                    break
                key, offset = _lenient_decode_from(data, offset)
                value, offset = _lenient_decode_from(data, offset)
                if key is None or value is None:
                    break
                try:
                    mapping[key] = value
                except TypeError:
                    mapping[str(key)] = value
            return mapping, offset
        length, offset = _lenient_read_uint(info, data, offset)
        for _ in range(length):
            if offset >= len(data):
                break
            key, offset = _lenient_decode_from(data, offset)
            if key is None and offset >= len(data):
                break
            value, offset = _lenient_decode_from(data, offset)
            if value is None and offset >= len(data):
                break
            try:
                mapping[key] = value
            except TypeError:
                mapping[str(key)] = value
        return mapping, offset

    if major_type == 6:
        tag_value, offset = _lenient_read_uint(info, data, offset)
        tagged_item, offset = _lenient_decode_from(data, offset)
        return {"tag": tag_value, "value": tagged_item}, offset

    if major_type == 7:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info == 22:
            return None, offset
        if info == 23:
            return None, offset
        if info == 24:
            if offset < len(data):
                value = data[offset]
            else:
                value = 0
            return value, offset + 1
        if info == 25:
            if offset + 2 <= len(data):
                raw = data[offset : offset + 2]
                offset += 2
                return struct.unpack(">e", raw)[0], offset
            return 0.0, len(data)
        if info == 26:
            if offset + 4 <= len(data):
                raw = data[offset : offset + 4]
                offset += 4
                return struct.unpack(">f", raw)[0], offset
            return 0.0, len(data)
        if info == 27:
            if offset + 8 <= len(data):
                raw = data[offset : offset + 8]
                offset += 8
                return struct.unpack(">d", raw)[0], offset
            return 0.0, len(data)
        return info, offset

    return None, offset
