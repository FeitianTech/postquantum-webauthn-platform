"""An AAGUID's GUID spelling, from its 16 bytes and nothing else."""
from __future__ import annotations

from server.app import aaguid


def test_sixteen_bytes_are_spelled_as_a_guid():
    assert aaguid.guid(bytes.fromhex("00112233445566778899aabbccddeeff")) == "00112233-4455-6677-8899-aabbccddeeff"


def test_anything_else_has_no_guid():
    assert aaguid.guid(b"\x00" * 15) is None
    assert aaguid.guid(b"\x00" * 17) is None
    assert aaguid.guid(bytearray(16)) is None
    assert aaguid.guid(memoryview(b"\x00" * 16)) is None
    assert aaguid.guid("00112233445566778899aabbccddeeff") is None
