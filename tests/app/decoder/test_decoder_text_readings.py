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


def test_an_odd_number_of_hexadecimal_digits_is_read_as_the_base64_it_may_be():
    # "abc" is no hexadecimal, but it is base64: 69 b7.
    assert pipeline._decode_binary_input("abc") == (b"\x69\xb7", "base64 or base64url")
    with pytest.raises(ValueError, match=r"text string declares 9 bytes.*read as base64: as hexadecimal, its 3 digits") as refused:
        decode_payload_text("abc")
    assert refused.value.offset == 0


def test_an_odd_number_of_hexadecimal_digits_that_is_no_base64_says_so():
    with pytest.raises(ValueError, match="Input is 5 hexadecimal digits, an odd number, so no bytes; and it is not base64"):
        decode_payload_text("abcde")
