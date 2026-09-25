"""How the decoder spells CBOR map keys in its JSON output."""
from __future__ import annotations

import pytest


def test_a_byte_string_map_key_is_shown_as_hex_like_a_byte_string_value():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    # {h'99999999': h'0102'}
    result = decode_module.decode_payload_text("a144999999994201 02".replace(" ", ""))

    assert result["data"]["decodedValue"] == {"99999999": "0102"}


def test_key_helpers_never_leak_a_python_bytes_repr():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._hex_json_safe({b"\x01\xff": {b"\x02": b"\x03"}}) == {"01ff": {"02": "03"}}
    assert decode_module._stringify_mapping_keys({b"\xaa": 1, 2: 3}) == {"aa": 1, "2": 3}


@pytest.mark.parametrize(
    ("hex_text", "decoded"),
    [
        # Array, map and tag keys are spelled in EDN, which the encoder can read
        # back, not as Python's repr of the decoded value.
        ("a1 c1 01 6161", {"1(1)": "a"}),  # was "{'tag': 1, 'value': 1}"
        ("a1 82 6161 6162 02", {'["a", "b"]': 2}),  # was "['a', 'b']"
        ("a1 82 4101 02 0a", {"[h'01', 2]": 10}),  # was "[b'\\x01', 2]"
        ("a1 a1 01 02 0a", {"{1: 2}": 10}),
        # Two NaN keys with different payloads are different keys: both are kept.
        ("a2 f97e00 01 f97e01 02", {"NaN": 1, "float'7e01'": 2}),
    ],
)
def test_keys_json_has_no_spelling_for_are_spelled_in_edn(hex_text, decoded):
    from server.app.decoder import decode_payload_text

    assert decode_payload_text(hex_text.replace(" ", ""))["data"]["decodedValue"] == decoded
