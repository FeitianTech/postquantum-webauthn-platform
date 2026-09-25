"""How the decoder reads the text it is given: JSON, PEM, hexadecimal, base64."""
from __future__ import annotations

import pytest

from server.app.decoder import decode_payload_text
from server.app.decoder.decode import pipeline


def test_the_json_text_null_is_read_as_base64():
    assert pipeline._decode_binary_input("null") == (b"\x9e\xe9\x65", "base64 or base64url")
    with pytest.raises(ValueError, match="additional information 30 is reserved"):
        decode_payload_text("null")


def test_a_0x_inside_hexadecimal_digits_is_dropped():
    assert pipeline._decode_binary_input("a0xb") == (b"\xab", "hex")
    assert pipeline._decode_binary_input("0xa0") == (b"\xa0", "hex")


def test_an_odd_number_of_hexadecimal_digits_is_no_reading():
    with pytest.raises(ValueError, match="does not appear to be valid base64, base64url, or hexadecimal"):
        pipeline._decode_binary_input("abc")
