"""``decoder.decode.binary_text``: binary text read as hex, base64 or base64url, strictly."""
from __future__ import annotations

import pytest

from server.app.decoder.decode import binary_text


def test_prose_is_refused_rather_than_read_with_its_stray_characters_dropped():
    # A decoder that does not validate would drop "*" and read "AQD".
    with pytest.raises(ValueError, match="does not appear to be valid"):
        binary_text.decode_binary_input("AQ*D")


def test_binary_input_reads_hex_and_base64_and_refuses_what_is_neither():
    hex_data, hex_encoding = binary_text.decode_binary_input("0abc")
    assert hex_data == bytes.fromhex("0abc")
    assert hex_encoding == "hex"

    # "abc" is not silently left-padded to "0abc"; the missing nibble is data
    # the caller never supplied. It is base64, and read as that.
    assert binary_text.decode_binary_input("abc") == (b"\x69\xb7", "base64 or base64url")
    with pytest.raises(ValueError, match="an odd number, so no bytes"):
        binary_text.decode_binary_input("abcde")

    with pytest.raises(ValueError, match="No binary data present"):
        binary_text.decode_binary_input("   ")


def test_a_field_is_read_as_binary_text_or_taken_as_the_bytes_it_is():
    assert binary_text.decode_binary_field("0abc") == (bytes.fromhex("0abc"), "hex")
    assert binary_text.decode_binary_field("AQ*D") is None
    assert binary_text.decode_binary_field(memoryview(b"abc")) == (b"abc", "binary")
    assert binary_text.decode_binary_field(bytearray(b"\x01")) == (b"\x01", "binary")
    assert binary_text.decode_binary_field(123) is None
