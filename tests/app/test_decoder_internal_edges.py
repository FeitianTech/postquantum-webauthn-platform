import base64

import cbor2
import pytest


def test_decode_binary_input_prefers_hex_when_candidate_is_valid_hex():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    decoded, encoding = decode_module._decode_binary_input("414243")

    assert decoded == b"ABC"
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
