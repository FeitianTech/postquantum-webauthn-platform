"""``decoder.decode.cbor_parser``: CBOR read strictly, or leniently with what it stepped over."""
import pytest

from server.app.decoder import values as decoder_values
from server.app.decoder.decode import cbor_parser as decode_cbor_parser


def test_parse_cbor_item_reads_one_byte_integers_and_rejects_reserved_additional_information():
    # 0x1e and 0x3e use additional information 30, which RFC 8949 reserves:
    # they are not the integers 30 and -31.

    unsigned_23, offset_u = decode_cbor_parser._parse_cbor_item(bytes([0x17]), 0)
    negative_24, offset_n = decode_cbor_parser._parse_cbor_item(bytes([0x37]), 0)
    assert (unsigned_23["value"], unsigned_23["summary"], offset_u) == (23, "23", 1)
    assert (negative_24["value"], offset_n) == (-24, 1)

    for initial in (0x1C, 0x1D, 0x1E, 0x3E, 0x5C, 0xFE):
        with pytest.raises(decode_cbor_parser._CborDecodingError, match="is reserved"):
            decode_cbor_parser._parse_cbor_item(bytes([initial]), 0)


def test_parse_cbor_item_byte_string_indefinite_and_truncated_forms():
    indefinite_node, indefinite_offset = decode_cbor_parser._parse_cbor_item(
        b"\x5f\x42ab\x41c\xff", 0
    )
    assert indefinite_node["indefinite"] is True
    assert indefinite_node["length"] == 3
    assert indefinite_node["summary"] == "bytes[3]"
    assert indefinite_offset == len(b"\x5f\x42ab\x41c\xff")

    with pytest.raises(decode_cbor_parser._CborDecodingError, match="byte string declares 5 bytes; 2 remain"):
        decode_cbor_parser._parse_cbor_item(b"\x58\x05xy", 0)

    truncated_node, truncated_offset, skipped = decode_cbor_parser.decode_item(b"\x58\x05xy", lenient=True)
    assert truncated_node["truncated"] is True
    assert truncated_node["hex"] == b"xy".hex()
    assert truncated_node["declaredLength"] == 5
    assert truncated_offset == len(b"\x58\x05xy")
    assert skipped[0]["message"] == "byte string declares 5 bytes; 2 remain"


def test_parse_cbor_item_text_string_indefinite_and_invalid_utf8():
    text_node, _ = decode_cbor_parser._parse_cbor_item(b"\x7f\x62hi\x61!\xff", 0)
    assert text_node["type"] == "text string"
    assert text_node["value"] == "hi!"
    assert text_node["indefinite"] is True

    with pytest.raises(decode_cbor_parser._CborDecodingError, match="not valid UTF-8"):
        decode_cbor_parser._parse_cbor_item(b"\x63\xff\xff\xff", 0)

    invalid_utf8_node, _, skipped = decode_cbor_parser.decode_item(b"\x63\xff\xff\xff", lenient=True)
    assert invalid_utf8_node["type"] == "text string"
    assert invalid_utf8_node["error"] == "Invalid UTF-8 in text string."
    assert [entry["code"] for entry in skipped] == ["invalid-utf8"]


def test_parse_cbor_item_array_map_tag_and_simple_float_values():
    array_node, _ = decode_cbor_parser._parse_cbor_item(b"\x82\x01\x02", 0)
    assert array_node["summary"] == "array[2]"

    map_node, _ = decode_cbor_parser._parse_cbor_item(b"\xbf\x61a\x01\xff", 0)
    assert map_node["summary"] == "map[1]"

    tag_node, _ = decode_cbor_parser._parse_cbor_item(b"\xc1\x01", 0)
    assert tag_node["type"] == "tag"
    assert tag_node["tag"] == 1

    half_float_node, _ = decode_cbor_parser._parse_cbor_item(b"\xf9\x3c\x00", 0)
    assert half_float_node["type"] == "float"
    assert half_float_node["precision"] == "half"


def test_structure_to_value_handles_chunks_and_unhashable_map_keys():
    byte_chunks_node = {
        "majorType": 2,
        "chunks": [
            {"majorType": 2, "hex": "4142"},
            {"majorType": 2, "hex": "43"},
        ],
    }
    assert decode_cbor_parser._structure_to_value(byte_chunks_node) == b"ABC"

    map_node = {
        "majorType": 5,
        "entries": [
            {
                "key": {"majorType": 4, "items": [{"majorType": 0, "value": 1}]},
                "value": {"majorType": 0, "value": 7},
            }
        ],
    }
    converted = decode_cbor_parser._structure_to_value(map_node)
    # An array key is a key of its own, spelled as the array it is.
    assert converted == {decoder_values.CborDiagnostic("[1]"): 7}
    assert decoder_values.stringify_mapping_keys(converted) == {"[1]": 7}


def test_decode_item_reads_indefinite_containers_and_never_makes_up_a_short_float():
    node, offset, _ = decode_cbor_parser.decode_item(b"\x9f\x01\x02\xff")
    assert decode_cbor_parser._structure_to_value(node) == [1, 2]
    assert offset == len(b"\x9f\x01\x02\xff")

    node, _, _ = decode_cbor_parser.decode_item(b"\xbf\x61a\x01\xff")
    assert decode_cbor_parser._structure_to_value(node) == {"a": 1}

    # Two of a double's eight bytes: not 0.0.
    with pytest.raises(decode_cbor_parser._CborDecodingError, match="double-precision float needs 8 bytes"):
        decode_cbor_parser.decode_item(b"\xfb\x00\x00")
    node, offset, skipped = decode_cbor_parser.decode_item(b"\xfb\x00\x00", lenient=True)
    assert node["type"] == "invalid"
    assert offset == 3
    assert [entry["code"] for entry in skipped] == ["truncated"]


def test_read_length_and_availability_helpers_raise_expected_errors():
    with pytest.raises(decode_cbor_parser._CborDecodingError):
        decode_cbor_parser._read_cbor_length(31, b"", 0, allow_indefinite=False)

    length, offset = decode_cbor_parser._read_cbor_length(31, b"", 0, allow_indefinite=True)
    assert length is None
    assert offset == 0


@pytest.mark.parametrize(
    ("data", "value", "end"),
    [(b"\x19\x00\x01", 1, 3), (b"\x1b" + b"\x00" * 8, 0, 9)],
)
def test_an_argument_is_read_from_the_bytes_its_additional_information_names(data, value, end):
    node, offset, _ = decode_cbor_parser.decode_item(data)

    assert (node["value"], offset) == (value, end)


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"", "the data ends where an item should start"),
        (b"\x1e", "additional information 30 is reserved"),
        (b"\x5f", "indefinite-length byte string has no break byte"),
        (b"\x5f\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\x7f", "indefinite-length text string has no break byte"),
        (b"\x7f\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\x9f\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\x82\x01", "array declares 2 items; the data ends after 1"),
        (b"\x82\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\xbf", "indefinite-length map has no break byte"),
        (b"\xbf\x61a", 'map key "a" has no value'),
        (b"\xbf\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\xa1", "map declares 1 entry; the data ends after 0"),
        (b"\xa1\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\x1f", "indefinite length is not allowed for this major type"),
        (b"\x3f", "indefinite length is not allowed for this major type"),
        (b"\xdf", "indefinite length is not allowed for this major type"),
    ],
)
def test_a_partial_or_invalid_item_is_refused_with_why(data, reason):
    with pytest.raises(decode_cbor_parser._CborDecodingError) as caught:
        decode_cbor_parser.decode_item(data)

    assert caught.value.reason == reason


def test_an_empty_indefinite_array_is_read_and_a_partial_container_closed_only_when_lenient():
    empty, end, _ = decode_cbor_parser.decode_item(b"\x9f\xff")
    short_array, _, short_skipped = decode_cbor_parser.decode_item(b"\x82\x01", lenient=True)
    orphan_key, _, orphan_skipped = decode_cbor_parser.decode_item(b"\xbf\x61a", lenient=True)

    assert (empty["length"], empty["indefinite"], end) == (0, True, 2)
    assert (short_array["length"], short_array["declaredLength"]) == (1, 2)
    assert [entry["code"] for entry in short_skipped] == ["truncated"]
    assert orphan_key["entries"] == []
    assert [entry["code"] for entry in orphan_skipped] == ["missing-map-value"]


@pytest.mark.parametrize(
    ("data", "fields"),
    [
        (b"\xf4", {"type": "boolean", "value": False}),
        (b"\xf6", {"type": "null"}),
        (b"\xf7", {"type": "undefined"}),
        (b"\xf0", {"summary": "simple(16)"}),
        (b"\xf8\x2a", {"type": "simple", "value": 42}),
        (b"\xfa\x3f\x80\x00\x00", {"precision": "single", "value": 1.0}),
        (b"\xfb\x3f\xf0" + b"\x00" * 6, {"precision": "double", "value": 1.0}),
        (b"\xf9\x3e\x00", {"precision": "half", "summary": "float(1.5)"}),
        (b"\xf9\x7c\x00", {"summary": "float(+Infinity)"}),
        (b"\xf9\xfc\x00", {"summary": "float(-Infinity)"}),
        (b"\xf9\x7e\x00", {"summary": "float(NaN)"}),
    ],
)
def test_simple_values_and_floats_are_read_with_their_kind_and_precision(data, fields):
    node, _, _ = decode_cbor_parser.decode_item(data)

    assert {key: node.get(key) for key in fields} == fields


# ``answer`` and the parser read nodes back to values; nodes the parser never makes
# only a direct call gives them.


@pytest.mark.parametrize(
    ("node", "value"),
    [
        ({"majorType": 7, "type": "null"}, None),
        ({"majorType": 7, "type": "undefined"}, decoder_values.CborDiagnostic("undefined")),
        ({"majorType": 7, "type": "boolean", "value": 0}, False),
        ({"majorType": 2, "hex": "not-hex"}, b""),
        ({"majorType": 3, "value": 123}, ""),
        ({"majorType": 4, "items": 123}, []),
        ({"majorType": 5, "entries": 123}, {}),
        ({"majorType": 6, "tag": 33, "value": {"majorType": 0, "value": 42}}, {"tag": 33, "value": 42}),
    ],
)
def test_a_node_is_read_back_to_its_value_and_a_malformed_one_to_an_empty_one(node, value):
    assert decode_cbor_parser._structure_to_value(node) == value


def test_a_map_node_keeps_only_its_well_formed_entries():
    node = {
        "majorType": 5,
        "entries": [
            "not-a-mapping",
            {"key": {"majorType": 0, "value": 1}, "value": {"majorType": 0, "value": 7}},
            {"key": None, "value": {"majorType": 0, "value": 9}},
        ],
    }

    assert decode_cbor_parser._structure_to_value(node) == {1: 7}


@pytest.mark.parametrize(
    ("data", "kept", "skipped"),
    [
        # An indefinite byte string whose break byte never comes: its chunks are kept.
        (b"\x5f\x41\x00", {"summary": "bytes[1]", "indefinite": True}, ("truncated", 0, "indefinite-length byte string has no break byte")),
        # Text declaring 3 bytes with 2 left: what is there is kept, and the length it declared.
        (b"\x63AJ", {"value": "AJ", "truncated": True, "declaredLength": 3}, ("truncated", 0, "text string declares 3 bytes; 2 remain")),
        # A simple value under 32 written in two bytes is no simple value.
        (b"\xf8\x10", {"type": "invalid", "summary": "invalid(h'f810')"}, ("invalid-simple-value", 0, "simple value 16 must be written in one byte")),
    ],
)
def test_a_short_unterminated_or_invalid_item_is_kept_when_lenient_and_refused_when_strict(data, kept, skipped):
    node, end, stepped_over = decode_cbor_parser.decode_item(data, lenient=True)

    assert {key: node.get(key) for key in kept} == kept
    assert end == len(data)
    assert [(entry["code"], entry["offset"], entry["message"]) for entry in stepped_over] == [skipped]
    with pytest.raises(decode_cbor_parser._CborDecodingError, match=skipped[2]):
        decode_cbor_parser.decode_item(data)
