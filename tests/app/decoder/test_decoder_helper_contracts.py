from __future__ import annotations

import pytest
from fido2.utils import ByteBuffer

from server.app.decoder import values as decoder_values
from server.app.decoder.decode import ctap as decode_ctap
from server.app.decoder.decode import json_input
from server.app.decoder.decode import pipeline as decode_pipeline


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
    assert decoder_values.key_identity(7) == ("int", 7)
    assert decoder_values.key_identity(True) == ("bool", True)
    assert decoder_values.key_identity("7") == ("text", "7")
    assert decoder_values.key_identity(b"\x07") == ("bytes", b"\x07")
    assert decoder_values.key_identity(ByteBuffer(b"\x07")) == ("bytes", b"\x07")
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


def test_decode_payload_text_dispatches_json_pem_and_binary_paths(monkeypatch, pipeline, response):
    with pytest.raises(ValueError, match="Decoder input is empty"):
        decode_pipeline.decode_payload_text("   ")

    monkeypatch.setattr(pipeline, "_read_json", lambda _v, **_kwargs: ({"a": 1}, []))
    monkeypatch.setattr(
        pipeline, "_decode_json_object", lambda value, raw_text=None, **_kwargs: {"kind": "json", "raw": raw_text, "value": value}
    )
    monkeypatch.setattr(response, "_prepare_decoder_response", lambda result: {"wrapped": result})
    assert decode_pipeline.decode_payload_text(" {\"a\": 1} ") == {
        "wrapped": {"kind": "json", "raw": '{"a": 1}', "value": {"a": 1}, "decodeMode": "strict"}
    }

    monkeypatch.setattr(pipeline, "_read_json", lambda _v, **_kwargs: (json_input.NOT_JSON, []))
    monkeypatch.setattr(pipeline, "_looks_like_pem", lambda _v: True)
    monkeypatch.setattr(pipeline, "_decode_pem_certificates", lambda _v: {"kind": "pem"})
    monkeypatch.setattr(response, "_prepare_decoder_response", lambda result: {"pem": result})
    assert decode_pipeline.decode_payload_text("-----BEGIN CERTIFICATE-----") == {
        "pem": {"kind": "pem", "decodeMode": "strict"}
    }

    monkeypatch.setattr(pipeline, "_looks_like_pem", lambda _v: False)
    monkeypatch.setattr(pipeline, "_decode_binary_input", lambda _v: (b"\x01\x02", "hex"))
    monkeypatch.setattr(
        pipeline,
        "_decode_binary_payload",
        lambda data, encoding, lenient=False: {"kind": "bin", "data": data, "encoding": encoding, "lenient": lenient},
    )
    monkeypatch.setattr(response, "_prepare_decoder_response", lambda result: {"bin": result})
    assert decode_pipeline.decode_payload_text("0102") == {
        "bin": {"kind": "bin", "data": b"\x01\x02", "encoding": "hex", "lenient": False, "decodeMode": "strict"}
    }
    assert decode_pipeline.decode_payload_text("0102", lenient=True)["bin"]["lenient"] is True


def test_decode_json_object_handles_client_data_and_plain_json(monkeypatch, pipeline):
    monkeypatch.setattr(pipeline, "_is_public_key_credential", lambda _v: False)
    monkeypatch.setattr(pipeline, "_is_client_data_dict", lambda _v: True)
    monkeypatch.setattr(pipeline, "_build_client_data_details", lambda value, raw_text=None: {"built": value, "raw": raw_text})

    client_result = decode_pipeline._decode_json_object({"type": "webauthn.get"}, raw_text="raw-json")
    assert client_result == {
        "format": "WebAuthn client data (JSON)",
        "inputEncoding": "json",
        "decoded": {"built": {"type": "webauthn.get"}, "raw": "raw-json"},
    }

    monkeypatch.setattr(pipeline, "_is_client_data_dict", lambda _v: False)
    plain_result = decode_pipeline._decode_json_object([1, 2, 3])
    assert plain_result == {
        "format": "JSON",
        "inputEncoding": "json",
        "decoded": [1, 2, 3],
    }


def test_decode_public_key_credential_uses_rawid_and_extension_fallbacks(monkeypatch, pipeline):
    monkeypatch.setattr(pipeline, "_decode_binary_field", lambda _v: None)

    credential = {
        "id": "credential-id",
        "type": "public-key",
        "rawId": "@@@not-binary@@@",
        "getClientExtensionResults": {"uvm": True},
        "response": {"other": "value"},
    }

    result = decode_pipeline._decode_public_key_credential(credential, raw_text="{\"x\":1}")

    assert result["format"] == "PublicKeyCredential"
    assert result["inputEncoding"] == "json"

    decoded = result["decoded"]
    assert decoded["rawId"] == {"raw": "@@@not-binary@@@"}
    assert decoded["clientExtensionResults"] == {"uvm": True}
    assert decoded["rawJson"] == '{"x":1}'
    assert decoded["response"] == {"other": "value"}


def test_decode_binary_field_handles_invalid_inputs(monkeypatch, pipeline):
    monkeypatch.setattr(
        pipeline,
        "_decode_binary_input",
        lambda _value: (_ for _ in ()).throw(ValueError("bad")),
    )
    assert decode_pipeline._decode_binary_field("bad") is None
    assert decode_pipeline._decode_binary_field(memoryview(b"abc")) == (b"abc", "binary")
    assert decode_pipeline._decode_binary_field(123) is None


def test_decode_binary_payload_prefers_pem_and_json_and_then_reads_strict_cbor(monkeypatch, pipeline):
    monkeypatch.setattr(decoder_values, "try_decode_utf8", lambda _data: "-----BEGIN CERTIFICATE-----")
    monkeypatch.setattr(pipeline, "_looks_like_pem", lambda text: text.startswith("-----BEGIN"))
    monkeypatch.setattr(pipeline, "_decode_pem_certificates", lambda _text: {"format": "X.509 certificate (PEM)", "decoded": {"pem": True}})
    monkeypatch.setattr(decoder_values, "binary_summary", lambda _data, _encoding=None: {"hex": "616263"})

    pem_result = decode_pipeline._decode_binary_payload(b"abc", "base64url")
    assert pem_result["format"] == "X.509 certificate (PEM)"
    assert pem_result["inputEncoding"] == "base64url"
    assert pem_result["binary"] == {"hex": "616263"}

    monkeypatch.setattr(decoder_values, "try_decode_utf8", lambda _data: '{"k": 1}')
    monkeypatch.setattr(pipeline, "_read_json", lambda _text, **_kwargs: ({"k": 1}, []))
    monkeypatch.setattr(pipeline, "_is_client_data_dict", lambda _obj: False)

    json_result = decode_pipeline._decode_binary_payload(b"abc", "hex")
    assert json_result == {
        "format": "JSON (binary)",
        "inputEncoding": "hex",
        "decoded": {"k": 1},
        "binary": {"hex": "616263"},
    }

    monkeypatch.setattr(decoder_values, "try_decode_utf8", lambda _data: None)
    monkeypatch.setattr(pipeline, "_try_decode_certificate_bytes", lambda _data, _enc: None)
    monkeypatch.setattr(pipeline, "_try_decode_attestation_object", lambda _data, _enc: None)
    monkeypatch.setattr(pipeline, "_try_decode_authenticator_data", lambda _data, _enc: None)

    # What nothing else claims is read as CBOR. Bytes that are not CBOR fail,
    # saying where, instead of coming back as an unexplained "Binary data".
    with pytest.raises(ValueError, match=r"offset 0 \(\$\): byte string declares 8 bytes; 1 remain"):
        decode_pipeline._decode_binary_payload(b"\x48\xaa", "hex")
