from __future__ import annotations

import base64

from fido2.utils import ByteBuffer

from server.app.decoder import values as decoder_values
from server.app.decoder.decode import authenticator_data as decode_authenticator_data
from server.app.decoder.decode import binary as decode_binary
from server.app.decoder.decode import cbor_parser as decode_cbor_parser
from server.app.decoder.decode import pipeline as decode_pipeline


def test_get_mapping_entry_reads_a_bytebuffer_key_as_the_byte_string_it_holds():
    assert decoder_values.get_mapping_entry({b"\x01": "bytes"}, ByteBuffer(b"\x01")) == "bytes"
    assert decoder_values.get_mapping_entry({1: "int"}, ByteBuffer(b"\x01")) is decoder_values.MISSING
    assert decoder_values.get_mapping_entry({"1": "str"}, ByteBuffer(b"\x01")) is decoder_values.MISSING


def test_decode_public_key_credential_marks_authentication_without_attestation(monkeypatch, pipeline):
    auth_bytes = b"\x00" * 37
    monkeypatch.setattr(
        decode_authenticator_data,
        "_describe_authenticator_data_bytes",
        lambda _value: {"parsed": True},
    )

    credential = {
        "id": "cred-id",
        "type": "public-key",
        "response": {
            "authenticatorData": base64.b64encode(auth_bytes).decode("ascii"),
        },
    }

    result = decode_pipeline._decode_public_key_credential(credential)
    assert result["format"] == "PublicKeyCredential (authentication)"
    assert result["decoded"]["response"]["authenticatorData"]["details"] == {"parsed": True}


def test_parse_cbor_item_covers_simple_and_single_double_precision_float_paths():
    simple_node, _ = decode_cbor_parser._parse_cbor_item(b"\xf8\x2a", 0)
    single_node, _ = decode_cbor_parser._parse_cbor_item(b"\xfa\x3f\x80\x00\x00", 0)
    double_node, _ = decode_cbor_parser._parse_cbor_item(
        b"\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00", 0
    )

    assert simple_node["type"] == "simple"
    assert simple_node["value"] == 42
    assert single_node["precision"] == "single"
    assert single_node["value"] == 1.0
    assert double_node["precision"] == "double"
    assert double_node["value"] == 1.0


def test_extract_authenticator_bytes_from_attestation_uses_raw_base64_and_handles_decode_failure(monkeypatch, binary):
    monkeypatch.setattr(
        binary,
        "_extract_bytes_from_binary",
        lambda _entry: None,
    )

    # {"authData": h'1122'}, as standard base64 with padding and spaces.
    extracted = decode_binary._extract_authenticator_bytes_from_attestation(
        {"raw": " oWhhdXRoRGF0YUIRIg== "}
    )
    assert extracted == b"\x11\x22"

    # 0x01 0x02 is CBOR, but not a map with authData.
    assert decode_binary._extract_authenticator_bytes_from_attestation({"raw": "AQI="}) is None

    monkeypatch.setattr(
        base64,
        "b64decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("invalid")),
    )
    assert (
        decode_binary._extract_authenticator_bytes_from_attestation({"raw": "AQI="})
        is None
    )


def test_extract_attestation_certificate_handles_non_string_chain_entries_and_serializer_errors(monkeypatch, pipeline):
    class _BytesEntry:
        def __bytes__(self):
            return b"\x01\x02"

    monkeypatch.setattr(
        pipeline,
        "serialize_attestation_certificate",
        lambda _cert: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert decode_pipeline._extract_attestation_certificate({"x5c": [_BytesEntry()]}) is None

    class _BadBytesEntry:
        def __bytes__(self):
            raise TypeError("bad-bytes")

    assert decode_pipeline._extract_attestation_certificate({"x5c": [_BadBytesEntry()]}) is None
