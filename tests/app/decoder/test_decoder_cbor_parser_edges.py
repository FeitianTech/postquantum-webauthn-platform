import pytest

from fido2.utils import ByteBuffer


def test_parse_cbor_item_reads_one_byte_integers_and_rejects_reserved_additional_information():
    # 0x1e and 0x3e use additional information 30, which RFC 8949 reserves:
    # they are not the integers 30 and -31.
    decode_module = pytest.importorskip("server.app.decoder.decode")

    unsigned_23, offset_u = decode_module._parse_cbor_item(bytes([0x17]), 0)
    negative_24, offset_n = decode_module._parse_cbor_item(bytes([0x37]), 0)
    assert (unsigned_23["value"], unsigned_23["summary"], offset_u) == (23, "23", 1)
    assert (negative_24["value"], offset_n) == (-24, 1)

    for initial in (0x1C, 0x1D, 0x1E, 0x3E, 0x5C, 0xFE):
        with pytest.raises(decode_module._CborDecodingError, match="is reserved"):
            decode_module._parse_cbor_item(bytes([initial]), 0)


def test_parse_cbor_item_byte_string_indefinite_and_truncated_forms():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    indefinite_node, indefinite_offset = decode_module._parse_cbor_item(
        b"\x5f\x42ab\x41c\xff", 0
    )
    assert indefinite_node["indefinite"] is True
    assert indefinite_node["length"] == 3
    assert indefinite_node["summary"] == "bytes[3]"
    assert indefinite_offset == len(b"\x5f\x42ab\x41c\xff")

    with pytest.raises(decode_module._CborDecodingError, match="byte string declares 5 bytes; 2 remain"):
        decode_module._parse_cbor_item(b"\x58\x05xy", 0)

    truncated_node, truncated_offset, skipped = decode_module.decode_item(b"\x58\x05xy", lenient=True)
    assert truncated_node["truncated"] is True
    assert truncated_node["hex"] == b"xy".hex()
    assert truncated_node["declaredLength"] == 5
    assert truncated_offset == len(b"\x58\x05xy")
    assert skipped[0]["message"] == "byte string declares 5 bytes; 2 remain"


def test_parse_cbor_item_text_string_indefinite_and_invalid_utf8():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    text_node, _ = decode_module._parse_cbor_item(b"\x7f\x62hi\x61!\xff", 0)
    assert text_node["type"] == "text string"
    assert text_node["value"] == "hi!"
    assert text_node["indefinite"] is True

    with pytest.raises(decode_module._CborDecodingError, match="not valid UTF-8"):
        decode_module._parse_cbor_item(b"\x63\xff\xff\xff", 0)

    invalid_utf8_node, _, skipped = decode_module.decode_item(b"\x63\xff\xff\xff", lenient=True)
    assert invalid_utf8_node["type"] == "text string"
    assert invalid_utf8_node["error"] == "Invalid UTF-8 in text string."
    assert [entry["code"] for entry in skipped] == ["invalid-utf8"]


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
    # An array key is a key of its own, spelled as the array it is.
    assert converted == {decode_module.CborDiagnostic("[1]"): 7}
    assert decode_module._stringify_mapping_keys(converted) == {"[1]": 7}


def test_decode_item_reads_indefinite_containers_and_never_makes_up_a_short_float():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    node, offset, _ = decode_module.decode_item(b"\x9f\x01\x02\xff")
    assert decode_module._structure_to_value(node) == [1, 2]
    assert offset == len(b"\x9f\x01\x02\xff")

    node, _, _ = decode_module.decode_item(b"\xbf\x61a\x01\xff")
    assert decode_module._structure_to_value(node) == {"a": 1}

    # Two of a double's eight bytes: not 0.0.
    with pytest.raises(decode_module._CborDecodingError, match="double-precision float needs 8 bytes"):
        decode_module.decode_item(b"\xfb\x00\x00")
    node, offset, skipped = decode_module.decode_item(b"\xfb\x00\x00", lenient=True)
    assert node["type"] == "invalid"
    assert offset == 3
    assert [entry["code"] for entry in skipped] == ["truncated"]


def test_read_length_and_availability_helpers_raise_expected_errors():
    decode_module = pytest.importorskip("server.app.decoder.decode")

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

    hex_data, hex_encoding = decode_module._decode_binary_input("0abc")
    assert hex_data == bytes.fromhex("0abc")
    assert hex_encoding == "hex"

    # "abc" is not silently left-padded to "0abc"; the missing nibble is data
    # the caller never supplied. It is base64, and read as that.
    assert decode_module._decode_binary_input("abc") == (b"\x69\xb7", "base64 or base64url")
    with pytest.raises(ValueError, match="an odd number, so no bytes"):
        decode_module._decode_binary_input("abcde")

    with pytest.raises(ValueError, match="No binary data present"):
        decode_module._decode_binary_input("   ")
