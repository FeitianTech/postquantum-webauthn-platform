"""``decoder.values``: the values the decoder reads and shows."""
from __future__ import annotations

from fido2.utils import ByteBuffer

from server.app.decoder import values as decoder_values


def test_a_bytebuffer_key_finds_the_byte_string_it_holds_and_nothing_else():
    key = ByteBuffer(b"\x01")

    assert decoder_values.get_mapping_entry({b"\x01": "bytes"}, key) == "bytes"
    assert decoder_values.get_mapping_entry({1: "int"}, key) is decoder_values.MISSING
    assert decoder_values.get_mapping_entry({"1": "str"}, key) is decoder_values.MISSING
