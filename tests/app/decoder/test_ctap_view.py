"""The spelling of values inside a CTAP view, and its exact reader (``decoder/ctap_view.py``)."""
from __future__ import annotations

import pytest
from hypothesis import event, given, settings

from server.app.decoder import ctap_view
from server.app.decoder.cbor_canonical import _canonical_cbor_dumps
from server.app.decoder.decode import canonical, cbor_parser

from .. import cbor_items


def _node(hex_text: str) -> dict:
    node, end, _skipped = cbor_parser.decode_item(bytes.fromhex(hex_text.replace(" ", "")))
    return node


@pytest.mark.parametrize(
    ("hex_text", "spelled"),
    [
        ("420102", "0102"),  # bytes: hex
        ("40", ""),  # empty bytes
        ("646162636b", "abck"),  # text that is no hex
        ("6430313032", '"0102" (text)'),  # text that is hex: typed
        ("60", '"" (text)'),  # empty text: typed, "" is empty bytes
        ("f6", None),  # null
        ("f5", True),
        ("3903e7", -1000),
        ("f93e00", "1.5 (float)"),
        ("fb3ff8000000000000", "1.5_3 (float)"),  # a double's width is kept
        ("f97e00", "NaN (float)"),
        ("c24101", "2(h'01') (tag)"),
        ("f0", "simple(16) (simple value)"),
        ("f7", "undefined (undefined)"),
        ("820102", [1, 2]),
    ],
)
def test_a_value_is_spelled_so_its_type_comes_back(hex_text, spelled):
    assert ctap_view.spell(_node(hex_text)) == spelled


def test_text_that_looks_typed_is_typed():
    assert ctap_view.spell_text("h'01' (bytes)") == "\"h'01' (bytes)\" (text)"
    assert ctap_view.spell_text("Temperature (C)") == "Temperature (C)"


@pytest.mark.parametrize(
    ("hex_text", "labels"),
    [
        ("a2 01 01 6131 02", ["1", '"1" (text)']),  # 1 and "1"
        ("a1 623031 01", ['"01" (text)']),  # text spelled like an integer
        ("a1 6461202332 01", ['"a #2" (text)']),  # text spelled like a numbered label
        ("a1 4101 01", ["h'01' (bytes)"]),  # bytes: always typed
        ("a1 f5 01", ["true (boolean)"]),
        ("a1 f6 01", ["null (null)"]),
        ("a1 8101 01", ["[1] (array)"]),
        ("a1 6161 01", ["a"]),
        ("a2 01 01 01 02", ["1", "1 #2"]),  # a repeated key: numbered, never lost
    ],
)
def test_a_map_key_is_labelled_so_its_type_comes_back(hex_text, labels):
    assert list(ctap_view.spell(_node(hex_text))) == labels


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (1.5, r"\$\{\"a\"\}: 1.5 is a JSON number with a fraction or exponent"),
        (2**64, "beyond what a CBOR integer holds"),
        ("1 (fmt)", r"\(fmt\) is not a value type"),
        ("invalid(bytes[1] at offset 1) (invalid)", "the decoder could not read that value"),
        ("h'zz' (bytes)", "EDN is not valid"),
    ],
)
def test_a_value_the_reader_cannot_read_is_refused_by_its_path(value, message):
    with pytest.raises(ValueError, match=message):
        ctap_view.read({"a": value})


@pytest.mark.parametrize(
    ("label", "message"),
    [
        ("01", r'the key "01" is no integer a CTAP view writes \(it writes 1\)'),
        ("1 #2", "is numbered"),
        (str(2**64), "beyond what a CBOR integer holds"),
        ("1 (txt)", r"\(txt\) is not a key type"),
    ],
)
def test_a_key_the_reader_cannot_read_is_refused(label, message):
    with pytest.raises(ValueError, match=message):
        ctap_view.read({label: 1})


def test_the_reader_reads_each_spelling_as_its_type():
    read = ctap_view.read(
        {"1": "0102", "a": '"0102" (text)', "-2": None, '"3" (text)': True, "h'01' (bytes)": "1.5 (float)", "x": "abc"}
    )

    assert read == {
        1: b"\x01\x02",
        "a": "0102",
        -2: None,
        "3": True,
        b"\x01": read[b"\x01"],
        "x": "abc",
    }
    assert _canonical_cbor_dumps(read[b"\x01"]) == bytes.fromhex("f93e00")


@settings(max_examples=2000)
@given(cbor_items.items)
def test_spelling_then_reading_gives_back_an_item_in_canonical_form(data):
    node, end, _skipped = cbor_parser.decode_item(data)
    try:
        rebuilt = _canonical_cbor_dumps(ctap_view.read(ctap_view.spell(node)))
    except ValueError:
        # Only a repeated key: a view holds one of them, numbering the other.
        assert any(finding["code"] == "duplicate-map-key" for finding in canonical.check(node, data))
        event("a repeated key, refused")
        return
    again, _end, _ = cbor_parser.decode_item(rebuilt)
    assert ctap_view.spell(again) == ctap_view.spell(node)
    if not canonical.check(node, data):
        event("canonical: the same bytes")
        assert rebuilt == data
    else:
        event("not canonical: the same view")
