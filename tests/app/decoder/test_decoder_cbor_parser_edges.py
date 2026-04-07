import pytest

from fido2.utils import ByteBuffer


def test_parse_cbor_item_unsigned_negative_and_special_integer_forms():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    unsigned_30, offset_u = decode_module._parse_cbor_item(bytes([0x1E]), 0)
    negative_31, offset_n = decode_module._parse_cbor_item(bytes([0x3E]), 0)

    assert unsigned_30["value"] == 30
    assert unsigned_30["summary"] == "30"
    assert negative_31["value"] == -31
    assert offset_u == 1
    assert offset_n == 1


def test_parse_cbor_item_byte_string_indefinite_and_truncated_forms():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    indefinite_node, indefinite_offset = decode_module._parse_cbor_item(
        b"\x5f\x42ab\x41c\xff", 0
    )
    assert indefinite_node["indefinite"] is True
    assert indefinite_node["length"] == 3
    assert indefinite_node["summary"] == "bytes[3]"
    assert indefinite_offset == len(b"\x5f\x42ab\x41c\xff")

    truncated_node, truncated_offset = decode_module._parse_cbor_item(b"\x58\x05xy", 0)
    assert truncated_node["truncated"] is True
    assert "truncated" in truncated_node["summary"]
    assert truncated_offset == len(b"\x58\x05xy")


def test_parse_cbor_item_text_string_indefinite_and_invalid_utf8():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    text_node, _ = decode_module._parse_cbor_item(b"\x7f\x62hi\x61!\xff", 0)
    assert text_node["type"] == "text string"
    assert text_node["value"] == "hi!"
    assert text_node["indefinite"] is True

    invalid_utf8_node, _ = decode_module._parse_cbor_item(b"\x63\xff\xff\xff", 0)
    assert invalid_utf8_node["type"] == "text string"
    assert invalid_utf8_node["error"] == "Invalid UTF-8 in text string."


def test_parse_cbor_item_array_map_tag_and_simple_float_values():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    array_node, _ = decode_module._parse_cbor_item(b"\x82\x01\x02", 0)
    assert array_node["summary"] == "array[2]"

    map_node, _ = decode_module._parse_cbor_item(b"\xbf\x61a\x01\xff", 0)
    assert map_node["summary"] == "map[1]"

    tag_node, _ = decode_module._parse_cbor_item(b"\xc1\x01", 0)
    assert tag_node["type"] == "tag"
    assert tag_node["tag"] == 1

    half_float_node, _ = decode_module._parse_cbor_item(b"\xf9\x3c\x00", 0)
    assert half_float_node["type"] == "float"
    assert half_float_node["precision"] == "half"


def test_structure_to_value_handles_chunks_and_unhashable_map_keys():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    byte_chunks_node = {
        "majorType": 2,
        "chunks": [
            {"majorType": 2, "hex": "4142"},
            {"majorType": 2, "hex": "43"},
        ],
    }
    assert decode_module._structure_to_value(byte_chunks_node) == b"ABC"

    map_node = {
        "majorType": 5,
        "entries": [
            {
                "key": {"majorType": 4, "items": [{"majorType": 0, "value": 1}]},
                "value": {"majorType": 0, "value": 7},
            }
        ],
    }
    converted = decode_module._structure_to_value(map_node)
    assert converted["[1]"] == 7


def test_lenient_decode_handles_indefinite_containers_and_incomplete_scalars():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    value, offset = decode_module._lenient_decode_from(b"\x9f\x01\x02\xff", 0)
    assert value == [1, 2]
    assert offset == len(b"\x9f\x01\x02\xff")

    mapping, _ = decode_module._lenient_decode_from(b"\xbf\x61a\x01\xff", 0)
    assert mapping == {"a": 1}

    float_value, float_offset = decode_module._lenient_decode_from(b"\xfb\x00\x00", 0)
    assert float_value == 0.0
    assert float_offset == len(b"\xfb\x00\x00")


def test_read_length_and_availability_helpers_raise_expected_errors():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    with pytest.raises(decode_module._CborDecodingError):
        decode_module._ensure_cbor_available(b"\x00", 1, 1)

    with pytest.raises(decode_module._CborDecodingError):
        decode_module._read_cbor_length(31, b"", 0, allow_indefinite=False)

    length, offset = decode_module._read_cbor_length(31, b"", 0, allow_indefinite=True)
    assert length is None
    assert offset == 0


def test_expand_cbor_value_and_binary_input_decoder_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    expanded = decode_module._expand_cbor_value(
        {
            "bytes": b"\x01\x02",
            "buffer": ByteBuffer(b"\x03\x04"),
            "items": [b"\x05", {"nested": b"\x06"}],
        }
    )
    assert expanded["bytes"]["hex"] == "0102"
    assert expanded["buffer"]["hex"] == "0304"
    assert expanded["items"][0]["hex"] == "05"
    assert expanded["items"][1]["nested"]["hex"] == "06"

    hex_data, hex_encoding = decode_module._decode_binary_input("abc")
    assert hex_data == bytes.fromhex("0abc")
    assert hex_encoding == "hex"

    with pytest.raises(ValueError, match="No binary data present"):
        decode_module._decode_binary_input("   ")
