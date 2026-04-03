import base64

import cbor2
import pytest


def test_decode_binary_input_prefers_hex_when_candidate_is_valid_hex():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    decoded, encoding = decode_module._decode_binary_input("414243")

    assert decoded == b"ABC"
    assert encoding == "hex"


def test_decode_binary_input_prefers_hex_for_ambiguous_alphabetic_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    decoded, encoding = decode_module._decode_binary_input("AAAA")

    assert decoded == bytes.fromhex("AAAA")
    assert encoding == "hex"


def test_decode_binary_input_accepts_base64url_without_padding():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    original = b"\xfb\xff"
    base64url_value = base64.urlsafe_b64encode(original).decode("ascii").rstrip("=")

    decoded, encoding = decode_module._decode_binary_input(base64url_value)

    assert decoded == original
    assert encoding == "base64url"


def test_decode_binary_input_rejects_invalid_binary_text():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    with pytest.raises(ValueError, match="Input does not appear to be valid"):
        decode_module._decode_binary_input("g$")


def test_parse_cbor_item_marks_truncated_byte_string():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    # Major type 2, additional info 26 -> 4-byte length; declares 5 bytes, carries only 2.
    payload = b"\x5a\x00\x00\x00\x05\x01\x02"

    node, offset = decode_module._parse_cbor_item(payload, 0)

    assert offset == len(payload)
    assert node["majorType"] == 2
    assert node["type"] == "byte string"
    assert node["length"] == 5
    assert node["truncated"] is True
    assert node["summary"] == "bytes[2] (truncated from 5)"


def test_parse_cbor_item_reports_invalid_utf8_text_string():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    payload = b"\x63\xff\xff\xff"
    node, offset = decode_module._parse_cbor_item(payload, 0)

    assert offset == len(payload)
    assert node["majorType"] == 3
    assert node["type"] == "text string"
    assert node["error"] == "Invalid UTF-8 in text string."
    assert node["hex"] == "ffffff"
    assert node["summary"] == "text[3]"


def test_try_decode_cbor_returns_none_for_empty_data():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._try_decode_cbor(b"", "hex") is None


def test_try_decode_cbor_reports_extra_cbor_objects_as_malformed():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    payload = cbor2.dumps({"a": 1}) + cbor2.dumps(2) + cbor2.dumps(3)

    result = decode_module._try_decode_cbor(payload, "base64url")

    assert result is not None
    assert result["format"] == "CBOR"
    assert result["inputEncoding"] == "base64url"
    malformed = result.get("malformed", [])
    assert any("additional CBOR object" in message for message in malformed)


def test_parse_cbor_item_rejects_break_code_outside_indefinite_container():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    with pytest.raises(
        decode_module._CborDecodingError,
        match="Unexpected break code outside indefinite container",
    ):
        decode_module._parse_cbor_item(b"\xff", 0)


def test_parse_cbor_item_rejects_non_bytes_segment_in_indefinite_byte_string():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    # 0x5f => start indefinite byte string; next chunk is text string (major type 3).
    payload = b"\x5f\x61a\xff"

    with pytest.raises(
        decode_module._CborDecodingError,
        match="Indefinite byte string segment is not a byte string",
    ):
        decode_module._parse_cbor_item(payload, 0)


def test_parse_cbor_item_rejects_non_text_segment_in_indefinite_text_string():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    # 0x7f => start indefinite text string; next chunk is byte string (major type 2).
    payload = b"\x7f\x41a\xff"

    with pytest.raises(
        decode_module._CborDecodingError,
        match="Indefinite text string segment is not a text string",
    ):
        decode_module._parse_cbor_item(payload, 0)


def test_parse_cbor_item_indefinite_map_with_orphan_key_keeps_completed_pairs():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    # 0xbf => indefinite map: {"a": 1, "b": <missing-value>}
    payload = b"\xbf\x61a\x01\x61b\xff"

    node, offset = decode_module._parse_cbor_item(payload, 0)

    assert node["majorType"] == 5
    assert node["type"] == "map"
    assert node["indefinite"] is True
    assert node["length"] == 1
    assert node["summary"] == "map[1]"
    assert node["entries"][0]["value"]["value"] == 1
    # The trailing break byte remains unread because the orphan key has no value.
    assert offset == len(payload) - 1


def test_parse_cbor_item_indefinite_array_without_break_keeps_parsed_items():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    # 0x9f => indefinite array containing a single nested definite array [1, 2],
    # with no break byte for the outer container.
    payload = b"\x9f\x82\x01\x02"

    node, offset = decode_module._parse_cbor_item(payload, 0)

    assert offset == len(payload)
    assert node["majorType"] == 4
    assert node["type"] == "array"
    assert node["indefinite"] is True
    assert node["length"] == 1
    assert node["summary"] == "array[1]"
    nested = node["items"][0]
    assert nested["type"] == "array"
    assert nested["length"] == 2


def test_try_decode_cbor_handles_ctap_prefix_without_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    result = decode_module._try_decode_cbor(b"\x01", "hex")

    assert result is not None
    assert result["format"] == "CBOR"
    assert result["decoded"]["decodedValue"]["summary"] == "Empty CBOR payload"
    assert result["decoded"]["ctap"]["kind"] == "command"
    assert result["decoded"]["ctap"]["payloadLength"] == 0


def test_try_decode_cbor_treats_ctap_padding_bytes_as_additional_objects():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    payload = b"\x01" + cbor2.dumps({"a": 1}) + b"\x00\xff"

    result = decode_module._try_decode_cbor(payload, "base64url")

    assert result is not None
    assert result["format"] == "CBOR"
    ctap = result["decoded"]["ctap"]
    assert ctap["kind"] == "command"
    malformed = result.get("malformed", [])
    assert any("additional CBOR object" in message for message in malformed)


def test_structure_to_value_preserves_integer_map_keys():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    structure = {
        "majorType": 5,
        "type": "map",
        "entries": [
            {
                "key": {"majorType": 0, "type": "unsigned", "value": 1},
                "value": {"majorType": 3, "type": "text string", "value": "first"},
            },
            {
                "key": {"majorType": 0, "type": "unsigned", "value": 2},
                "value": {"majorType": 3, "type": "text string", "value": "second"},
            },
        ],
    }

    value = decode_module._structure_to_value(structure)

    assert value == {1: "first", 2: "second"}


def test_structure_to_value_falls_back_to_string_for_unhashable_keys():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    structure = {
        "majorType": 5,
        "type": "map",
        "entries": [
            {
                "key": {
                    "majorType": 4,
                    "type": "array",
                    "items": [
                        {"majorType": 0, "type": "unsigned", "value": 1},
                        {"majorType": 0, "type": "unsigned", "value": 2},
                    ],
                },
                "value": {"majorType": 3, "type": "text string", "value": "value"},
            }
        ],
    }

    value = decode_module._structure_to_value(structure)

    assert value == {"[1, 2]": "value"}


def test_lenient_decode_from_indefinite_array_without_break_keeps_items():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    payload = b"\x9f\x01\x02"

    value, offset = decode_module._lenient_decode_from(payload)

    assert value == [1, 2]
    assert offset == len(payload)


def test_lenient_decode_from_indefinite_map_with_orphan_key_keeps_completed_pairs():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    payload = b"\xbf\x61k\x01\x61m"

    value, offset = decode_module._lenient_decode_from(payload)

    assert value == {"k": 1}
    assert offset == len(payload)


def test_decode_cbor_sequence_uses_lenient_fallback_for_reserved_additional_info_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    structures, values, consumed_total, remaining = decode_module._decode_cbor_sequence(b"\x1c")

    assert consumed_total == 1
    assert remaining == b""
    assert values == [28]
    assert len(structures) == 1
    assert structures[0]["lenient"] is True
    assert structures[0]["summary"] == "Decoded value (lenient)"


def test_expand_cbor_value_stringifies_mapping_keys_and_summarizes_binary_values():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    expanded = decode_module._expand_cbor_value(
        {1: b"\xaa\xbb", "nested": [b"\xcc", {2: b"\xdd"}]}
    )

    assert sorted(expanded.keys()) == ["1", "nested"]
    assert expanded["1"]["hex"] == "aabb"
    assert expanded["nested"][0]["hex"] == "cc"
    assert expanded["nested"][1]["2"]["hex"] == "dd"
