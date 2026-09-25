"""How the decoder reads the text it is given: JSON, PEM, hexadecimal, base64."""
from __future__ import annotations

import pytest

from server.app.decoder import decode_payload_text
from server.app.decoder.decode import pipeline


def test_the_json_text_null_is_json_null():
    # It is also base64 (9e e9 65), bytes no reading reads whole.
    assert decode_payload_text("null")["data"] == {"json": None}
    assert decode_payload_text(b"null".hex())["data"] == {"json": None}


def test_0x_is_a_hexadecimal_prefix_only_at_the_start():
    assert pipeline._decode_binary_input("a0xb") == (b"\x6b\x4c\x5b", "base64 or base64url")
    assert pipeline._decode_binary_input("0xa0") == (b"\xa0", "hex")
    assert pipeline._decode_binary_input("0Xde:ad") == (b"\xde\xad", "hex")


def test_an_odd_number_of_hexadecimal_digits_is_no_reading():
    with pytest.raises(ValueError, match="does not appear to be valid base64, base64url, or hexadecimal"):
        pipeline._decode_binary_input("abc")
