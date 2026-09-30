from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fido2.utils import ByteBuffer

from ... import encoding


def format_hex_bytes_lines(data: bytes, bytes_per_line: int = 16) -> list[str]:
    """Colon-separated hex, ``bytes_per_line`` bytes to a line."""

    return [data[start : start + bytes_per_line].hex(":") for start in range(0, len(data), bytes_per_line)]


def format_hex_string_lines(hex_string: str, bytes_per_line: int = 16) -> list[str]:
    data = encoding.try_decode_hex(
        hex_string, allow_separators=True, allow_odd_length=True
    )
    if data is None:
        return [hex_string]
    return format_hex_bytes_lines(data, bytes_per_line)


def decode_asn1_octet_string(data: bytes) -> bytes:
    """Best-effort decode of a DER-encoded OCTET STRING payload."""

    current = data
    for _ in range(4):
        if not current or current[0] != 0x04 or len(current) < 2:
            break

        length_byte = current[1]
        offset = 2

        if length_byte == 0x80:
            break

        if length_byte & 0x80:
            length_octets = length_byte & 0x7F
            if length_octets == 0 or len(current) < offset + length_octets:
                break
            length = int.from_bytes(current[offset : offset + length_octets], "big")
            offset += length_octets
        else:
            length = length_byte

        if len(current) < offset + length:
            break

        next_value = current[offset : offset + length]
        if next_value == current:
            break
        current = next_value

    return current


def encode_base64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return encoding.encode_base64url(data)


def make_json_safe(value: Any) -> Any:
    """Recursively convert bytes-like WebAuthn option values into JSON-friendly data."""
    if isinstance(value, (bytes, bytearray, memoryview, ByteBuffer)):
        return encode_base64url(bytes(value))
    if isinstance(value, Mapping):
        return {key: make_json_safe(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [make_json_safe(item) for item in value]
    return value
