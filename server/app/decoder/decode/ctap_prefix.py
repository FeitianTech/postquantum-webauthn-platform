"""The CTAP command or status byte a decoder input may start with.

A request is a command byte and its CBOR parameters; a response is a status
byte, followed by CBOR only on success (CTAP 2.2 section 8).
"""
from __future__ import annotations

from typing import Any

from .. import ctap_tables


def _extract_ctap_prefix(data: bytes) -> tuple[dict[str, Any] | None, bytes]:
    """Read the CTAP command or status byte ``data`` starts with.

    A request is a command byte and its CBOR parameters; a response is a status
    byte, followed by CBOR only on success. So a byte with a payload after it is
    a command, or SUCCESS; a byte on its own is an error status or a command sent
    without parameters. Where a lone byte names both (0x04 is GET_INFO and
    INVALID_SEQ), both readings are given rather than one picked.
    """

    if not data:
        return None, data
    code, payload = data[0], data[1:]
    command = ctap_tables.COMMANDS.get(code)
    status = ctap_tables.STATUSES.get(code)

    if code == ctap_tables.SUCCESS:
        command = None
    elif payload:
        status = None

    if command is None and status is None:
        return None, data

    prefix: dict[str, Any] = {"code": code, "codeHex": f"0x{code:02x}"}
    readings: list[str] = []
    if command is not None:
        prefix["command"] = command
        readings.append(f"{command} command")
    if status is not None:
        prefix["status"] = status
        readings.append(f"{status} status")
    prefix["kind"] = " or ".join(kind for kind, name in (("command", command), ("status", status)) if name)
    prefix["meaning"] = " or ".join(readings)
    return prefix, payload


def _is_padding_bytes(data: bytes) -> bool:
    if not data:
        return True
    return all(byte in (0x00, 0xFF) for byte in data)
