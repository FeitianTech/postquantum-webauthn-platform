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
