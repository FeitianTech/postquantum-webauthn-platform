from __future__ import annotations

from fido2.utils import ByteBuffer

from server.app.decoder import values as decoder_values
from server.app.decoder.decode import binary_text, credential_json
from server.app.decoder.decode import ctap as decode_ctap


def test_extract_ctap_prefix_handles_empty_command_status_and_unknown_codes():
    prefix, remaining = decode_ctap._extract_ctap_prefix(b"")
    assert prefix is None
    assert remaining == b""

    prefix, remaining = decode_ctap._extract_ctap_prefix(b"\x01\xaa\xbb")
    assert prefix == {
        "code": 1,
        "codeHex": "0x01",
        "command": "MAKE_CREDENTIAL",
        "meaning": "MAKE_CREDENTIAL command",
        "kind": "command",
    }
    assert remaining == b"\xaa\xbb"

    prefix, remaining = decode_ctap._extract_ctap_prefix(b"\x00\xcc")
    assert prefix == {
        "code": 0,
        "codeHex": "0x00",
        "status": "SUCCESS",
        "meaning": "SUCCESS status",
        "kind": "status",
    }
    assert remaining == b"\xcc"

    prefix, remaining = decode_ctap._extract_ctap_prefix(b"\x7f\xdd")
    assert prefix is None
    assert remaining == b"\x7f\xdd"


def test_is_padding_bytes_distinguishes_padding_from_content():
    assert decode_ctap._is_padding_bytes(b"") is True
    assert decode_ctap._is_padding_bytes(b"\x00\xff\x00") is True
    assert decode_ctap._is_padding_bytes(b"\x00\x01\xff") is False


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


def test_decode_public_key_credential_uses_rawid_and_extension_fallbacks(monkeypatch):
    monkeypatch.setattr(binary_text, "decode_binary_field", lambda _v: None)

    credential = {
        "id": "credential-id",
        "type": "public-key",
        "rawId": "@@@not-binary@@@",
        "getClientExtensionResults": {"uvm": True},
        "response": {"other": "value"},
    }

    result = credential_json.decode_public_key_credential(credential, raw_text="{\"x\":1}")

    assert result["format"] == "PublicKeyCredential"
    assert result["inputEncoding"] == "json"

    decoded = result["decoded"]
    assert decoded["rawId"] == {"raw": "@@@not-binary@@@"}
    assert decoded["clientExtensionResults"] == {"uvm": True}
    assert decoded["rawJson"] == '{"x":1}'
    assert decoded["response"] == {"other": "value"}
