"""``decoder.values``: the values the decoder reads and shows."""

from __future__ import annotations

from fido2.utils import ByteBuffer

from server.app.decoder import values as decoder_values


def test_a_bytebuffer_key_finds_the_byte_string_it_holds_and_nothing_else():
    key = ByteBuffer(b"\x01")

    assert decoder_values.get_mapping_entry({b"\x01": "bytes"}, key) == "bytes"
    assert decoder_values.get_mapping_entry({1: "int"}, key) is decoder_values.MISSING
    assert decoder_values.get_mapping_entry({"1": "str"}, key) is decoder_values.MISSING


def test_key_identity_names_the_cbor_type_of_a_key():
    assert decoder_values.key_identity(7) == ("integer", 7)
    assert decoder_values.key_identity(True) == ("simple", 21)
    assert decoder_values.key_identity(False) == ("simple", 20)
    assert decoder_values.key_identity("7") == ("text", "7")
    assert decoder_values.key_identity(b"\x07") == ("bytes", "07")
    assert decoder_values.key_identity(ByteBuffer(b"\x07")) == ("bytes", "07")
    assert decoder_values.key_identity(1.5) == ("other", 1.5)


def test_get_mapping_entry_matches_keys_by_exact_type_and_missing_sentinel():
    mapping = {
        1: "int-key",
        b"\x02": "bytes-key",
        "custom": "custom-key",
    }

    assert decoder_values.get_mapping_entry(mapping, 1) == "int-key"
    assert decoder_values.get_mapping_entry(mapping, "1") is decoder_values.MISSING
    assert decoder_values.get_mapping_entry(mapping, True) is decoder_values.MISSING
    assert decoder_values.get_mapping_entry(mapping, 2) is decoder_values.MISSING
    assert decoder_values.get_mapping_entry(mapping, b"\x02") == "bytes-key"
    assert decoder_values.get_mapping_entry(mapping, "missing", "custom") == "custom-key"
    assert decoder_values.get_mapping_entry(mapping, "does-not-exist") is decoder_values.MISSING
    assert decoder_values.get_mapping_entry([1, 2, 3], 1) is decoder_values.MISSING


def test_stringify_and_hex_helpers_convert_nested_values():
    payload = {
        1: [b"\xaa", {"x": memoryview(b"\xbb")}],
        "buf": ByteBuffer(b"\xcc"),
    }

    stringified = decoder_values.stringify_mapping_keys(payload)
    assert sorted(stringified.keys()) == ["1", "buf"]
    assert stringified["1"][0] == b"\xaa"

    hex_only = decoder_values.make_hex_only(payload)
    assert hex_only == {
        "1": ["aa", {"x": "bb"}],
        "buf": "cc",
    }
    assert decoder_values.make_hex_only(payload) == hex_only
