"""The one JSON-safe converter, bytes as unpadded base64url through containers, and the one byte reading."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fido2.utils import ByteBuffer

from server.app.json_values import as_bytes, make_json_safe


def test_bytes_of_every_kind_become_unpadded_base64url_through_every_container():
    converted = make_json_safe(
        {
            "raw": b"\x01\x02",
            "list": [bytearray(b"\x03"), memoryview(b"\x04")],
            "tuple": (ByteBuffer(b"\x05"),),
            "set": {b"\x06"},
        }
    )

    assert converted == {"raw": "AQI", "list": ["Aw", "BA"], "tuple": ["BQ"], "set": ["Bg"]}


def test_keys_keep_their_types_unless_asked_for_strings():
    cose = {1: 2, 3: -7, -1: b"\xaa\xbb"}

    assert make_json_safe(cose) == {1: 2, 3: -7, -1: "qrs"}
    assert make_json_safe(cose, string_keys=True) == {"1": 2, "3": -7, "-1": "qrs"}
    assert make_json_safe({"nested": {1: b"\x01"}}, string_keys=True) == {"nested": {"1": "AQ"}}


def test_a_datetime_is_utc_to_the_second_and_a_uuid_its_string():
    timestamp = datetime(2026, 4, 3, 12, 34, 56, 123456, tzinfo=timezone.utc)
    test_uuid = uuid.UUID("7701a390-8b53-4ce0-bf7c-b331569b8d1a")

    assert make_json_safe({"time": timestamp, "uuid": test_uuid}) == {
        "time": "2026-04-03T12:34:56Z",
        "uuid": "7701a390-8b53-4ce0-bf7c-b331569b8d1a",
    }


def test_anything_else_is_left_as_it_is():
    assert make_json_safe({"text": "a", "number": 1.5, "none": None, "flag": True}) == {
        "text": "a",
        "number": 1.5,
        "none": None,
        "flag": True,
    }


def test_as_bytes_reads_every_byte_string_kind_and_nothing_else():
    assert as_bytes(ByteBuffer(b"abc")) == b"abc"
    assert as_bytes(b"abc") == b"abc"
    assert as_bytes(bytearray(b"abc")) == b"abc"
    assert as_bytes(memoryview(b"xyz")) == b"xyz"
    assert as_bytes("abc") is None
    assert as_bytes([0x61]) is None
