"""decoder/edn spells a parsed CBOR item as EDN that describes its bytes exactly.

RFC 8949 section 8 and 8.1, with draft-ietf-cbor-edn-literals' ``float'..'``
for a NaN that has no decimal spelling: an encoding indicator appears exactly
where the bytes are not in preferred serialization.
"""
from __future__ import annotations

import pytest

from server.app.decoder import edn
from server.app.decoder.decode.cbor_parser import decode_item


def _spell(hex_text: str, **options) -> str:
    data = bytes.fromhex(hex_text.replace(" ", ""))
    node, end, _skipped = decode_item(data)
    assert end == len(data)
    return edn.spell(node, **options)


@pytest.mark.parametrize(
    ("hex_text", "expected"),
    [
        # Integers: the argument width where it is not the shortest.
        ("00", "0"), ("17", "23"), ("1818", "24"), ("1805", "5_0"), ("190005", "5_1"), ("1a00000005", "5_2"),
        ("1b0000000000000005", "5_3"), ("190100", "256"), ("1bffffffffffffffff", "18446744073709551615"),
        ("20", "-1"), ("3818", "-25"), ("3900ff", "-256_1"), ("3bffffffffffffffff", "-18446744073709551616"),
        # Byte and text strings, their length widths, and indefinite lengths chunk by chunk.
        ("40", "h''"), ("4201ff", "h'01ff'"), ("5801 01", "h'01'_0"), ("590001 41", "h'41'_1"),
        ("5f ff", "''_"), ("5f 4101 5801 02 ff", "(_ h'01', h'02'_0)"), ("5f 40 ff", "(_ h'')"),
        ("60", '""'), ("6161", '"a"'), ("7801 61", '"a"_0'), ("7f ff", '""_'), ("7f 6161 6162 ff", '(_ "a", "b")'),
        # Arrays and maps: indicators after the bracket, entries in wire order, duplicates kept.
        ("80", "[]"), ("9800", "[_0]"), ("9f ff", "[_ ]"), ("82 01 02", "[1, 2]"), ("98 02 01 02", "[_0 1, 2]"),
        ("9f 01 02 ff", "[_ 1, 2]"), ("a0", "{}"), ("bf ff", "{_ }"), ("a1 01 02", "{1: 2}"),
        ("b8 01 01 02", "{_0 1: 2}"), ("bf 61 61 01 ff", '{_ "a": 1}'),
        ("a2 01 6161 01 6162", '{1: "a", 1: "b"}'), ("a2 6131 00 01 00", '{"1": 0, 1: 0}'),
        ("a2 02 00 01 00", "{2: 0, 1: 0}"),
        # Tags, the tag number's width, nested tags.
        ("c1 00", "1(0)"), ("d8 01 00", "1_0(0)"), ("c1 c2 00", "1(2(0))"), ("d9 0100 40", "256(h'')"),
        # Simple values.
        ("f4", "false"), ("f5", "true"), ("f6", "null"), ("f7", "undefined"), ("e0", "simple(0)"),
        ("f3", "simple(19)"), ("f8 20", "simple(32)"), ("f8 ff", "simple(255)"),
    ],
)
def test_every_item_is_spelled_as_its_bytes(hex_text, expected):
    assert _spell(hex_text) == expected


@pytest.mark.parametrize(
    ("hex_text", "expected"),
    [
        # Preferred width: no indicator. A wider one than the value needs: its width.
        ("f9 3e00", "1.5"), ("fa 3fc00000", "1.5_2"), ("fb 3ff8000000000000", "1.5_3"),
        ("fb 3ff199999999999a", "1.1"), ("fa 47c35000", "100000.0"), ("f9 8000", "-0.0"), ("fa 80000000", "-0.0_2"),
        ("f9 0001", "5.960464477539063e-08"), ("fa 00000001", "1.401298464324817e-45"),
        ("fb 0000000000000001", "5.0e-324"), ("fb 4415af1d78b58c40", "1.0e+20"),
        ("f9 7c00", "Infinity"), ("f9 fc00", "-Infinity"), ("fa 7f800000", "Infinity_2"),
        ("fb fff0000000000000", "-Infinity_3"),
        # The quiet NaN is NaN; any other NaN is its bits.
        ("f9 7e00", "NaN"), ("fa 7fc00000", "NaN_2"), ("fb 7ff8000000000000", "NaN_3"),
        ("f9 7e01", "float'7e01'"), ("f9 fe00", "float'fe00'"), ("fa 7fc00001", "float'7fc00001'"),
        ("fb 7ff8000000000001", "float'7ff8000000000001'"),
    ],
)
def test_a_float_is_spelled_at_the_width_it_was_written(hex_text, expected):
    assert _spell(hex_text) == expected


def test_text_is_quoted_with_json_escapes_and_written_as_itself_otherwise():
    text = 'q"b\\n\nr\rt\tz\x00d\x7fl é😀'
    encoded = text.encode()
    item = bytes([0x78, len(encoded)]) + encoded
    assert edn.spell(decode_item(item)[0]) == '"q\\"b\\\\n\\nr\\rt\\tz\\u0000d\\u007fl\\u2028é😀"'


def test_a_container_of_containers_spans_lines_unless_inline():
    assert _spell("82 81 01 a1 01 82 02 03") == "[\n  [1],\n  {\n    1: [2, 3]\n  }\n]"
    assert _spell("82 81 01 a1 01 82 02 03", inline=True) == "[[1], {1: [2, 3]}]"
    # A map's keys stay on their entry's line.
    assert _spell("a1 81 01 81 02") == "{\n  [1]: [2]\n}"


def test_a_node_built_without_its_head_is_spelled_as_the_shortest():
    assert edn.spell({"majorType": 0, "value": 1}) == "1"
    assert edn.spell({"majorType": 4, "items": [{"majorType": 1, "value": -2}]}) == "[-2]"
    assert edn.spell({"majorType": 7, "type": "float", "precision": "double", "value": 0.5}) == "0.5_3"


@pytest.mark.parametrize(
    "hex_text",
    [
        "1c",  # reserved additional information: an invalid node
        "62 fffe",  # text that is not UTF-8
        "43 0102",  # a byte string cut short
        "a1 6161",  # a map whose one key has no value: the entry is dropped
        "82 01",  # an array missing an item
    ],
)
def test_an_item_the_lenient_parser_could_not_read_whole_is_not_spelled(hex_text):
    node, _end, skipped = decode_item(bytes.fromhex(hex_text.replace(" ", "")), lenient=True)
    assert skipped
    with pytest.raises(ValueError):
        edn.spell(node)
