from __future__ import annotations

from cryptography.hazmat import asn1

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


def der_octet_string_content(data: bytes) -> bytes:
    """The content of a DER OCTET STRING; ``data`` as it is when it is not one."""

    try:
        return asn1.decode_der(bytes, data)
    except ValueError:
        return data


def encode_base64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return encoding.encode_base64url(data)
