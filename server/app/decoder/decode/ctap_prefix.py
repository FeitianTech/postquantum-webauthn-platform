"""The CTAP command or status byte a decoder input may start with.

A request is a command byte and its CBOR parameters; a response is a status
byte, followed by CBOR only on success (CTAP 2.2 section 8).

A command byte can also be the first byte of one CBOR item: 0x41 is the head of
a one-byte byte string. When what follows the byte is not well-formed CBOR but
the whole input is one well-formed item, the input is read as that item -- a
reading that parses, rather than an error for input that is well-formed -- and
a ``ctap-prefix-not-read`` finding names the command reading not taken.
"""
from __future__ import annotations

from typing import Any

from .. import ctap_tables
from . import cbor_parser


def _extract_ctap_prefix(data: bytes) -> tuple[dict[str, Any] | None, bytes]:
    """Read the CTAP command or status byte ``data`` starts with, if it is read as one.

    A request is a command byte and its CBOR parameters; a response is a status
    byte, followed by CBOR only on success. So a byte with a payload after it is
    a command, or SUCCESS; a byte on its own is an error status or a command sent
    without parameters. Where a lone byte names both (0x04 is GET_INFO and
    INVALID_SEQ), both readings are given rather than one picked.
    """

    prefix, payload = _read_prefix(data)
    if prefix is not None and _read_from_the_first_byte(data, payload):
        return None, data
    return prefix, payload


def _read_from_the_first_byte(data: bytes, payload: bytes) -> bool:
    """Whether a prefix byte's payload is not CBOR while the whole input is one item."""

    return bool(payload) and not _parses(payload) and _is_one_item(data)


def _parses(data: bytes) -> bool:
    try:
        cbor_parser.decode_item(data)
    except cbor_parser._CborDecodingError:
        return False
    return True


def _is_one_item(data: bytes) -> bool:
    try:
        _node, end, _skipped = cbor_parser.decode_item(data)
    except cbor_parser._CborDecodingError:
        return False
    return end == len(data)


def prefix_not_read(data: bytes) -> list[dict[str, Any]]:
    """The finding for input whose first byte is a command byte but was read as the start of one item."""

    prefix, payload = _read_prefix(data)
    if prefix is None or not _read_from_the_first_byte(data, payload):
        return []
    return [
        {
            "code": "ctap-prefix-not-read",
            "category": "input",
            "offset": 0,
            "path": "$",
            "message": (
                f"{prefix['codeHex']} is also the {prefix['meaning']} byte, but what follows it is not "
                "well-formed CBOR; the whole input is one well-formed CBOR item, and was read as that"
            ),
        }
    ]


def _read_prefix(data: bytes) -> tuple[dict[str, Any] | None, bytes]:

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
