"""How the decoder reads the text it is given: JSON, PEM, hexadecimal, base64."""
from __future__ import annotations

import base64

import pytest

from server.app.decoder.decode import binary_text
from server.app.decoder.decode.text import decode_payload_text
from tests.app.python_fido2_vectors import GSR2_DER


def _pem(der: bytes) -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def test_blank_text_is_refused_as_empty():
    with pytest.raises(ValueError, match="Decoder input is empty"):
        decode_payload_text(" \n\t ")


def test_pem_text_sent_as_hexadecimal_is_the_certificate_it_holds():
    as_text = decode_payload_text(_pem(GSR2_DER))
    as_hex = decode_payload_text(_pem(GSR2_DER).encode().hex())

    assert as_hex["type"] == as_text["type"] == "X.509 certificate"
    assert as_hex["data"]["raw"] == GSR2_DER.hex()
    assert as_hex["data"]["pem"] == as_text["data"]["pem"]
    assert as_hex["findings"] == []


def test_json_text_sent_as_hexadecimal_is_the_json_it_holds():
    assert decode_payload_text(b'{"k": 1}'.hex()) == {
        "success": True,
        "type": "JSON",
        "data": {"json": {"k": 1}},
        "decodeMode": "strict",
        "findings": [],
        "malformed": [],
    }


def test_the_json_text_null_is_json_null():
    # It is also base64 (9e e9 65), bytes no reading reads whole.
    assert decode_payload_text("null")["data"] == {"json": None}
    assert decode_payload_text(b"null".hex())["data"] == {"json": None}


def test_0x_is_a_hexadecimal_prefix_only_at_the_start():
    assert binary_text.decode_binary_input("a0xb") == (b"\x6b\x4c\x5b", "base64 or base64url")
    assert binary_text.decode_binary_input("0xa0") == (b"\xa0", "hex")
    assert binary_text.decode_binary_input("0Xde:ad") == (b"\xde\xad", "hex")


def test_an_odd_number_of_hexadecimal_digits_is_read_as_the_base64_it_may_be():
    # "abc" is no hexadecimal, but it is base64: 69 b7.
    assert binary_text.decode_binary_input("abc") == (b"\x69\xb7", "base64 or base64url")
    with pytest.raises(ValueError, match=r"text string declares 9 bytes.*read as base64: as hexadecimal, its 3 digits") as refused:
        decode_payload_text("abc")
    assert refused.value.offset == 0


def test_an_odd_number_of_hexadecimal_digits_that_is_no_base64_says_so():
    with pytest.raises(ValueError, match="Input is 5 hexadecimal digits, an odd number, so no bytes; and it is not base64"):
        decode_payload_text("abcde")


def test_a_der_certificate_sent_as_base64url_is_the_certificate_it_holds():
    answer = decode_payload_text(base64.urlsafe_b64encode(GSR2_DER).decode().rstrip("="))

    assert answer["type"] == "X.509 certificate"
    assert answer["data"]["raw"] == GSR2_DER.hex()
    assert answer["data"]["parsedX5c"]["subject"] == decode_payload_text(_pem(GSR2_DER))["data"]["parsedX5c"]["subject"]
