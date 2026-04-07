from __future__ import annotations

import pytest
from fido2.utils import ByteBuffer


def test_extract_ctap_prefix_handles_empty_command_status_and_unknown_codes():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    prefix, remaining = decode_module._extract_ctap_prefix(b"")
    assert prefix is None
    assert remaining == b""

    prefix, remaining = decode_module._extract_ctap_prefix(b"\x01\xaa\xbb")
    assert prefix == {
        "code": 1,
        "codeHex": "0x01",
        "meaning": "AuthenticatorMakeCredential command",
        "kind": "command",
    }
    assert remaining == b"\xaa\xbb"

    prefix, remaining = decode_module._extract_ctap_prefix(b"\x00\xcc")
    assert prefix == {
        "code": 0,
        "codeHex": "0x00",
        "meaning": "Success status",
        "kind": "status",
    }
    assert remaining == b"\xcc"

    prefix, remaining = decode_module._extract_ctap_prefix(b"\x7f\xdd")
    assert prefix is None
    assert remaining == b"\x7f\xdd"


def test_is_padding_bytes_distinguishes_padding_from_content():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._is_padding_bytes(b"") is True
    assert decode_module._is_padding_bytes(b"\x00\xff\x00") is True
    assert decode_module._is_padding_bytes(b"\x00\x01\xff") is False


def test_int_to_key_bytes_handles_zero_and_large_values():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._int_to_key_bytes(0) == b"\x00"
    assert decode_module._int_to_key_bytes(1) == b"\x01"
    assert decode_module._int_to_key_bytes(300) == b"\x01,"


def test_generate_key_variants_covers_int_string_hex_and_byte_inputs():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert list(decode_module._generate_key_variants(7)) == [7, "7", b"\x07"]
    assert list(decode_module._generate_key_variants(-7)) == [-7, "-7"]

    variants_decimal = list(decode_module._generate_key_variants(" 15 "))
    assert variants_decimal == [" 15 ", 15, b"\x0f"]

    variants_hex = list(decode_module._generate_key_variants("0x10"))
    assert variants_hex == ["0x10", 16, b"\x10"]

    variants_bad_hex = list(decode_module._generate_key_variants("0xzz"))
    assert variants_bad_hex == ["0xzz"]

    variants_empty = list(decode_module._generate_key_variants("   "))
    assert variants_empty == ["   "]

    variants_bytes = list(decode_module._generate_key_variants(b"\x01\x02"))
    assert variants_bytes == [b"\x01\x02", b"\x01\x02", 258, "258"]


def test_get_mapping_entry_uses_variant_lookup_and_missing_sentinel():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    mapping = {
        1: "int-key",
        b"\x02": "bytes-key",
        "custom": "custom-key",
    }

    assert decode_module._get_mapping_entry(mapping, "1") == "int-key"
    assert decode_module._get_mapping_entry(mapping, 2) == "bytes-key"
    assert decode_module._get_mapping_entry(mapping, "custom") == "custom-key"
    assert decode_module._get_mapping_entry(mapping, "does-not-exist") is decode_module._MISSING
    assert decode_module._get_mapping_entry([1, 2, 3], "1") is decode_module._MISSING


def test_coerce_cbor_bytes_supports_supported_binary_types():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._coerce_cbor_bytes(ByteBuffer(b"abc")) == b"abc"
    assert decode_module._coerce_cbor_bytes(b"abc") == b"abc"
    assert decode_module._coerce_cbor_bytes(bytearray(b"abc")) == b"abc"
    assert decode_module._coerce_cbor_bytes(memoryview(b"abc")) == b"abc"
    assert decode_module._coerce_cbor_bytes("abc") is None


def test_stringify_and_hex_helpers_convert_nested_values():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    payload = {
        1: [b"\xaa", {"x": memoryview(b"\xbb")}],
        "buf": ByteBuffer(b"\xcc"),
    }

    stringified = decode_module._stringify_mapping_keys(payload)
    assert sorted(stringified.keys()) == ["1", "buf"]
    assert stringified["1"][0] == b"\xaa"

    hex_only = decode_module._make_hex_only(payload)
    assert hex_only == {
        "1": ["aa", {"x": "bb"}],
        "buf": "cc",
    }
    assert decode_module._hex_json_safe(payload) == hex_only


def test_json_safe_with_stringified_keys_wraps_make_json_safe(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(decode_module, "make_json_safe", lambda _value: {1: "ok", 2: "yes"})

    assert decode_module._json_safe_with_stringified_keys(object()) == {"1": "ok", "2": "yes"}


def test_decode_payload_text_dispatches_json_pem_and_binary_paths(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    with pytest.raises(ValueError, match="Decoder input is empty"):
        decode_module.decode_payload_text("   ")

    monkeypatch.setattr(decode_module, "_try_parse_json", lambda _v: {"a": 1})
    monkeypatch.setattr(decode_module, "_decode_json_object", lambda value, raw_text=None: {"kind": "json", "raw": raw_text, "value": value})
    monkeypatch.setattr(decode_module, "_prepare_decoder_response", lambda result: {"wrapped": result})
    assert decode_module.decode_payload_text(" {\"a\": 1} ") == {
        "wrapped": {"kind": "json", "raw": '{"a": 1}', "value": {"a": 1}}
    }

    monkeypatch.setattr(decode_module, "_try_parse_json", lambda _v: None)
    monkeypatch.setattr(decode_module, "_looks_like_pem", lambda _v: True)
    monkeypatch.setattr(decode_module, "_decode_pem_certificates", lambda _v: {"kind": "pem"})
    monkeypatch.setattr(decode_module, "_prepare_decoder_response", lambda result: {"pem": result})
    assert decode_module.decode_payload_text("-----BEGIN CERTIFICATE-----") == {"pem": {"kind": "pem"}}

    monkeypatch.setattr(decode_module, "_looks_like_pem", lambda _v: False)
    monkeypatch.setattr(decode_module, "_decode_binary_input", lambda _v: (b"\x01\x02", "hex"))
    monkeypatch.setattr(decode_module, "_decode_binary_payload", lambda data, encoding: {"kind": "bin", "data": data, "encoding": encoding})
    monkeypatch.setattr(decode_module, "_prepare_decoder_response", lambda result: {"bin": result})
    assert decode_module.decode_payload_text("0102") == {
        "bin": {"kind": "bin", "data": b"\x01\x02", "encoding": "hex"}
    }


def test_decode_json_object_handles_client_data_and_plain_json(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(decode_module, "_is_public_key_credential", lambda _v: False)
    monkeypatch.setattr(decode_module, "_is_client_data_dict", lambda _v: True)
    monkeypatch.setattr(decode_module, "_build_client_data_details", lambda value, raw_text=None: {"built": value, "raw": raw_text})

    client_result = decode_module._decode_json_object({"type": "webauthn.get"}, raw_text="raw-json")
    assert client_result == {
        "format": "WebAuthn client data (JSON)",
        "inputEncoding": "json",
        "decoded": {"built": {"type": "webauthn.get"}, "raw": "raw-json"},
    }

    monkeypatch.setattr(decode_module, "_is_client_data_dict", lambda _v: False)
    plain_result = decode_module._decode_json_object([1, 2, 3])
    assert plain_result == {
        "format": "JSON",
        "inputEncoding": "json",
        "decoded": [1, 2, 3],
    }


def test_decode_public_key_credential_uses_rawid_and_extension_fallbacks(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(decode_module, "_decode_binary_field", lambda _v: None)

    credential = {
        "id": "credential-id",
        "type": "public-key",
        "rawId": "@@@not-binary@@@",
        "getClientExtensionResults": {"uvm": True},
        "response": {"other": "value"},
    }

    result = decode_module._decode_public_key_credential(credential, raw_text="{\"x\":1}")

    assert result["format"] == "PublicKeyCredential"
    assert result["inputEncoding"] == "json"

    decoded = result["decoded"]
    assert decoded["rawId"] == {"raw": "@@@not-binary@@@"}
    assert decoded["clientExtensionResults"] == {"uvm": True}
    assert decoded["rawJson"] == '{"x":1}'
    assert decoded["response"] == {"other": "value"}


def test_decode_binary_field_and_try_parse_json_handle_invalid_inputs(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        decode_module,
        "_decode_binary_input",
        lambda _value: (_ for _ in ()).throw(ValueError("bad")),
    )
    assert decode_module._decode_binary_field("bad") is None
    assert decode_module._decode_binary_field(memoryview(b"abc")) == (b"abc", "binary")
    assert decode_module._decode_binary_field(123) is None

    assert decode_module._try_parse_json("{\"a\": 1}") == {"a": 1}
    assert decode_module._try_parse_json("not-json") is None
    assert decode_module._try_parse_json(None) is None


def test_decode_binary_payload_prefers_pem_and_json_and_then_binary_fallback(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(decode_module, "_try_decode_utf8", lambda _data: "-----BEGIN CERTIFICATE-----")
    monkeypatch.setattr(decode_module, "_looks_like_pem", lambda text: text.startswith("-----BEGIN"))
    monkeypatch.setattr(decode_module, "_decode_pem_certificates", lambda _text: {"format": "X.509 certificate (PEM)", "decoded": {"pem": True}})
    monkeypatch.setattr(decode_module, "_binary_summary", lambda _data, _encoding=None: {"hex": "616263"})

    pem_result = decode_module._decode_binary_payload(b"abc", "base64url")
    assert pem_result["format"] == "X.509 certificate (PEM)"
    assert pem_result["inputEncoding"] == "base64url"
    assert pem_result["binary"] == {"hex": "616263"}

    monkeypatch.setattr(decode_module, "_try_decode_utf8", lambda _data: '{"k": 1}')
    monkeypatch.setattr(decode_module, "_try_parse_json", lambda _text: {"k": 1})
    monkeypatch.setattr(decode_module, "_is_client_data_dict", lambda _obj: False)

    json_result = decode_module._decode_binary_payload(b"abc", "hex")
    assert json_result == {
        "format": "JSON (binary)",
        "inputEncoding": "hex",
        "decoded": {"k": 1},
        "binary": {"hex": "616263"},
    }

    monkeypatch.setattr(decode_module, "_try_decode_utf8", lambda _data: None)
    monkeypatch.setattr(decode_module, "_try_decode_certificate_bytes", lambda _data, _enc: None)
    monkeypatch.setattr(decode_module, "_try_decode_attestation_object", lambda _data, _enc: None)
    monkeypatch.setattr(decode_module, "_try_decode_authenticator_data", lambda _data, _enc: None)
    monkeypatch.setattr(decode_module, "_try_decode_cbor", lambda _data, _enc: None)

    fallback_result = decode_module._decode_binary_payload(b"abc", "hex")
    assert fallback_result == {
        "format": "Binary data",
        "inputEncoding": "hex",
        "decoded": {"hex": "616263"},
    }
