from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from fido2.utils import ByteBuffer


def test_get_mapping_entry_reads_a_bytebuffer_key_as_the_byte_string_it_holds():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._get_mapping_entry({b"\x01": "bytes"}, ByteBuffer(b"\x01")) == "bytes"
    assert decode_module._get_mapping_entry({1: "int"}, ByteBuffer(b"\x01")) is decode_module._MISSING
    assert decode_module._get_mapping_entry({"1": "str"}, ByteBuffer(b"\x01")) is decode_module._MISSING


def test_decode_public_key_credential_marks_authentication_without_attestation(monkeypatch, pipeline):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_bytes = b"\x00" * 37
    monkeypatch.setattr(
        pipeline,
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

    result = decode_module._decode_public_key_credential(credential)
    assert result["format"] == "PublicKeyCredential (authentication)"
    assert result["decoded"]["response"]["authenticatorData"]["details"] == {"parsed": True}


def test_parse_cbor_item_covers_simple_and_single_double_precision_float_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    simple_node, _ = decode_module._parse_cbor_item(b"\xf8\x2a", 0)
    single_node, _ = decode_module._parse_cbor_item(b"\xfa\x3f\x80\x00\x00", 0)
    double_node, _ = decode_module._parse_cbor_item(
        b"\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00", 0
    )

    assert simple_node["type"] == "simple"
    assert simple_node["value"] == 42
    assert single_node["precision"] == "single"
    assert single_node["value"] == 1.0
    assert double_node["precision"] == "double"
    assert double_node["value"] == 1.0


def test_att_stmt_extension_header_and_authenticator_data_fallback_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert (
        decode_module._format_certificate_extension_header(
            {
                "includeOidInHeader": False,
                "oid": "1.2.3",
                "friendlyName": "1.2.3",
            }
        )
        == "1.2.3"
    )
    assert (
        decode_module._format_certificate_extension_header(
            {
                "includeOidInHeader": False,
                "friendlyName": "Friendly name only",
            }
        )
        == "Friendly name only"
    )

    assert decode_module._build_authenticator_data_lines(
        None,
        {"rpIdHash": {"hex": "aabb"}},
    ) == ["aabb"]


def test_build_subject_key_identifier_lines_derives_digest_when_ski_extension_missing(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    class _Extensions:
        def get_extension_for_oid(self, _oid):
            raise x509.ExtensionNotFound(
                "missing",
                ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            )

    class _Certificate:
        extensions = _Extensions()

        def public_key(self):
            return object()

    monkeypatch.setattr(
        x509,
        "load_der_x509_certificate",
        lambda _der: _Certificate(),
    )
    monkeypatch.setattr(
        x509.SubjectKeyIdentifier,
        "from_public_key",
        lambda _public_key: SimpleNamespace(digest=b"\x01\x23"),
    )

    result = decode_module._build_subject_key_identifier_lines(
        {"derBase64": base64.b64encode(b"\x30\x01").decode("ascii")}
    )
    assert result == decode_module.format_hex_bytes_lines(b"\x01\x23")


def test_extract_authenticator_bytes_from_attestation_uses_raw_base64_and_handles_decode_failure(monkeypatch, binary):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        binary,
        "_extract_bytes_from_binary",
        lambda _entry: None,
    )

    # {"authData": h'1122'}, as standard base64 with padding and spaces.
    extracted = decode_module._extract_authenticator_bytes_from_attestation(
        {"raw": " oWhhdXRoRGF0YUIRIg== "}
    )
    assert extracted == b"\x11\x22"

    # 0x01 0x02 is CBOR, but not a map with authData.
    assert decode_module._extract_authenticator_bytes_from_attestation({"raw": "AQI="}) is None

    monkeypatch.setattr(
        base64,
        "b64decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("invalid")),
    )
    assert (
        decode_module._extract_authenticator_bytes_from_attestation({"raw": "AQI="})
        is None
    )


def test_extract_attestation_certificate_handles_non_string_chain_entries_and_serializer_errors(monkeypatch, pipeline):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    class _BytesEntry:
        def __bytes__(self):
            return b"\x01\x02"

    monkeypatch.setattr(
        pipeline,
        "serialize_attestation_certificate",
        lambda _cert: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert decode_module._extract_attestation_certificate({"x5c": [_BytesEntry()]}) is None

    class _BadBytesEntry:
        def __bytes__(self):
            raise TypeError("bad-bytes")

    assert decode_module._extract_attestation_certificate({"x5c": [_BadBytesEntry()]}) is None
