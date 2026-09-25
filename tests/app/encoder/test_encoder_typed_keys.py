"""Typed key spellings the decoder writes are read back by the module that wrote them.

``decode/keys.qualified_key_text`` spells a key that JSON cannot tell apart with
its type -- ``"1" (text)``, ``h'01' (bytes)``, ``1.5 (float)``, ``[1, 2]
(array)`` -- and ``read_json_key`` reads each back to that key. The encoder
used to write such a spelling as a literal text key. A spelling it does not
recognise is an error naming the key, never a guess.
"""
from __future__ import annotations

import json

import pytest

from server.app.decoder import decode_payload_text, edn
from server.app.decoder.decode import keys
from server.app.decoder.decode.cbor_parser import CborDiagnostic, _map_key, decode_item
from server.app.decoder.encode import encode_payload_text


def _cbor(value: dict) -> str:
    return encode_payload_text(json.dumps(value), "cbor")["data"]["binary"]["hex"]


@pytest.mark.parametrize(
    ("label", "key"),
    [
        ('"1" (text)', "1"),
        ('"with \\"quotes\\"" (text)', 'with "quotes"'),
        ("h'01ff' (bytes)", b"\x01\xff"),
        ("true (boolean)", CborDiagnostic("true", "boolean")),
        ("1.5 (float)", CborDiagnostic("1.5", "float")),
        ("float'7e01' (float)", CborDiagnostic("float'7e01'", "float")),
        ("null (null)", CborDiagnostic("null", "null")),
        ("simple(16) (simple value)", CborDiagnostic("simple(16)", "simple value")),
        ("[1, 2] (array)", CborDiagnostic("[1, 2]", "array")),
        ("{1: 2} (map)", CborDiagnostic("{1: 2}", "map")),
        ("1(1) (tag)", CborDiagnostic("1(1)", "tag")),
        # Not typed spellings: text keys, JSON's meaning.
        ("1", "1"),
        ("Temperature (C)", "Temperature (C)"),
        ("x (text)", "x (text)"),
    ],
)
def test_a_typed_spelling_is_read_as_the_key_it_names(label, key):
    assert keys.read_json_key(label) == key


@pytest.mark.parametrize(
    ("label", "reason"),
    [
        ("h'zz' (bytes)", "pairs of hex digits"),
        ('"1" (txt)', "(txt) is not a key type"),
        ("1 (fmt)", "(fmt) is not a key type"),
        ("1.5 (text)", "1.5 is not a text"),
        ("true (float)", "true is not a float"),
        ("true (boolean) #2", "a numbered spelling"),
        ("h'ff' (not UTF-8) (text, not UTF-8)", "could not read that key"),
    ],
)
def test_a_spelling_it_does_not_recognise_is_an_error_naming_the_key(label, reason):
    with pytest.raises(ValueError) as raised:
        keys.read_json_key(label)

    assert str(raised.value).startswith(f"The key {json.dumps(label)} is not a key the encoder can read: ")
    assert reason in str(raised.value)


@pytest.mark.parametrize(
    "key_item",
    ["6131", "4101", "f5", "f6", "f7", "f0", "f93e00", "fb3ff8000000000000", "f97e01", "8201 6161", "a10102",
     "c101", "7f6161ff", "f97c00"],
)
def test_the_spelling_of_every_key_the_decoder_makes_reads_back_to_it(key_item):
    node = decode_item(bytes.fromhex(f"a1{key_item.replace(' ', '')}00"))[0]
    key = _map_key(node["entries"][0]["key"])

    assert keys.read_json_key(keys.qualified_key_text(key)) == key


def test_a_text_key_spelled_like_a_typed_key_is_spelled_with_its_type_and_reads_back():
    item = edn.encode('{"1 (fmt)": 1, "\\"1\\" (text)": 2, "h\'01\' (bytes)": 3}')

    decoded = decode_payload_text(item.hex())["data"]["decodedValue"]

    assert list(decoded) == ['"1 (fmt)" (text)', '"\\"1\\" (text)" (text)', '"h\'01\' (bytes)" (text)']
    assert [keys.read_json_key(label) for label in decoded] == ["1 (fmt)", '"1" (text)', "h'01' (bytes)"]
    assert _cbor(decoded) == item.hex()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({'"1" (text)': 1}, "a1613101"),
        ({"h'01' (bytes)": 1}, "a1410101"),
        ({"1.5 (float)": 1}, "a1f93e0001"),
        ({"1.5_3 (float)": 1}, "a1fb3ff800000000000001"),  # written as its EDN says
        ({"true (boolean)": 1, "null (null)": 2}, "a2f501f602"),
        ({"[1, 2] (array)": 1}, "a182010201"),
        ({"x": {"1(1) (tag)": 1}}, "a16178a1c10101"),  # nested maps too
    ],
)
def test_the_generic_encoder_writes_the_key_a_typed_spelling_names(value, expected):
    assert _cbor(value) == expected


@pytest.mark.parametrize(
    ("value", "keys_named"),
    [
        ({"a": 1, '"a" (text)': 2}, '"a" and "\\"a\\" (text)"'),
        ({"1.0 (float)": 1, "1.0_2 (float)": 2}, '"1.0 (float)" and "1.0_2 (float)"'),  # one number, two widths
        ({"h'01' (bytes)": 1, "h'01'_0 (bytes)": 2}, "\"h'01' (bytes)\" and \"h'01'_0 (bytes)\""),
    ],
)
def test_two_json_keys_that_name_one_cbor_key_are_refused(value, keys_named):
    with pytest.raises(ValueError, match="name the same CBOR key") as raised:
        _cbor(value)
    assert keys_named in str(raised.value)


def test_a_decoded_value_with_keys_json_spells_apart_encodes_back():
    # {h'01': 1, "01": 2}: bytes and text, spelled h'01' (bytes) and "01" (text).
    decoded = decode_payload_text("a2410101623031 02".replace(" ", ""))["data"]["decodedValue"]

    assert decoded == {"h'01' (bytes)": 1, '"01" (text)': 2}
    assert _cbor(decoded) == "a2410101623031" + "02"


def test_the_integer_1_spelled_plainly_is_not_guessed_back():
    # {1: "a", "1": "b"}: the integer is spelled "1", which JSON reads as text; the
    # encoder refuses rather than guess which key it was. EDN rebuilds it.
    result = decode_payload_text("a2016161613161 62".replace(" ", ""))

    with pytest.raises(ValueError, match=r'The keys "1" and "\\"1\\" \(text\)" at \$ name the same CBOR key'):
        _cbor(result["data"]["decodedValue"])
    assert edn.encode(result["data"]["edn"]).hex() == "a201616161316162"


def test_a_typed_key_at_ctap_member_level_is_refused_as_not_a_member():
    auth = "00" * 32 + "01" + "00000001"
    view = {"getAssertionResponse": {"2 (authData)": {"raw": auth}, "3 (signature)": "0102", '"fmt" (text)': "x"}}

    with pytest.raises(ValueError, match=r'is a text key, not a CTAP member'):
        encode_payload_text(json.dumps({"ctapDecoded": view}), "cbor")


def test_a_user_entity_whose_keys_collide_in_json_is_refused_naming_both():
    auth = "00" * 32 + "01" + "00000001"
    item = edn.encode(f"{{2: h'{auth}', 3: h'0102', 4: {{\"id\": h'01', 5: \"integer\", \"5\": \"text\"}}}}")
    decoded = decode_payload_text(item.hex())["data"]

    with pytest.raises(ValueError, match=r'The keys "5" and "\\"5\\" \(text\)" at user name the same CBOR key'):
        encode_payload_text(json.dumps(decoded), "cbor")
