from __future__ import annotations

import base64

import pytest

from tests.fido2.attestation.test_attestation import _GSR2_DER


def _pem_block(der_bytes: bytes) -> str:
    body = base64.b64encode(der_bytes).decode("ascii")
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----"


def test_decode_public_key_credential_includes_signature_and_user_handle_summaries(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    def _decode_binary(value):
        if value == "sig":
            return b"\xaa\xbb", "base64"
        if value == "uh":
            return b"\x01\x02", "base64url"
        return None

    monkeypatch.setattr(decode_module, "_decode_binary_field", _decode_binary, raising=False)

    result = decode_module._decode_public_key_credential(
        {
            "id": "credential-id",
            "type": "public-key",
            "response": {
                "signature": "sig",
                "userHandle": "uh",
            },
        }
    )

    response = result["decoded"]["response"]
    assert response["signature"]["binary"]["hex"] == "aabb"
    assert response["userHandle"]["binary"]["hex"] == "0102"


def test_decode_pem_certificates_skips_decode_errors_and_uses_single_certificate_payload_shape():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    invalid_body_block = "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----"
    pem_text = "\n".join([invalid_body_block, _pem_block(_GSR2_DER)])

    result = decode_module._decode_pem_certificates(pem_text)
    assert result["format"] == "X.509 certificate (PEM)"
    assert isinstance(result["decoded"], dict)
    assert "rawPem" in result["decoded"]
    assert "certificates" not in result["decoded"]


def test_decode_binary_payload_uses_authenticator_data_path_when_other_binary_decoders_fail(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(decode_module, "_try_decode_utf8", lambda _data: None, raising=False)
    monkeypatch.setattr(decode_module, "_try_decode_certificate_bytes", lambda _data, _enc: None, raising=False)
    monkeypatch.setattr(decode_module, "_try_decode_attestation_object", lambda _data, _enc: None, raising=False)
    monkeypatch.setattr(
        decode_module,
        "_try_decode_authenticator_data",
        lambda _data, enc: {"format": "Authenticator data (binary)", "inputEncoding": enc},
        raising=False,
    )

    result = decode_module._decode_binary_payload(b"raw", "hex")
    assert result["format"] == "Authenticator data (binary)"
    assert result["inputEncoding"] == "hex"


def test_decode_binary_input_uses_urlsafe_fallback_when_strict_base64_decode_fails(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    original_b64decode = decode_module.base64.b64decode

    def _patched_b64decode(*args, **kwargs):
        if kwargs.get("validate"):
            raise ValueError("strict decode failed")
        return original_b64decode(*args, **kwargs)

    monkeypatch.setattr(
        decode_module.base64,
        "b64decode",
        _patched_b64decode,
        raising=False,
    )

    data, encoding = decode_module._decode_binary_input("AQID")
    assert data == b"\x01\x02\x03"
    assert encoding == "base64url"


def test_cbor_parser_handles_indefinite_container_breaks_partial_data_and_parser_failures(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._read_cbor_length(25, b"\x00\x01", 0) == (1, 2)
    assert decode_module._read_cbor_length(27, b"\x00" * 8, 0) == (0, 8)
    assert decode_module._read_cbor_length(30, b"\x00" * 8, 0) == (0, 8)

    with pytest.raises(decode_module._CborDecodingError):
        decode_module._parse_cbor_item(b"", 0)

    byte_indefinite_empty, _ = decode_module._parse_cbor_item(b"\x5f", 0)
    byte_indefinite_error, _ = decode_module._parse_cbor_item(b"\x5f\xd8", 0)
    assert byte_indefinite_empty["length"] == 0
    assert byte_indefinite_error["length"] == 0

    text_indefinite_empty, _ = decode_module._parse_cbor_item(b"\x7f", 0)
    text_indefinite_error, _ = decode_module._parse_cbor_item(b"\x7f\xd8", 0)
    assert text_indefinite_empty["value"] == ""
    assert text_indefinite_error["value"] == ""

    array_indefinite_break, _ = decode_module._parse_cbor_item(b"\x9f\xff", 0)
    array_indefinite_parse_error, _ = decode_module._parse_cbor_item(b"\x9f\xd8", 0)
    array_definite_short, _ = decode_module._parse_cbor_item(b"\x82\x01", 0)
    array_definite_parse_error, _ = decode_module._parse_cbor_item(b"\x82\xd8", 0)
    assert array_indefinite_break["length"] == 0
    assert array_indefinite_parse_error["length"] == 0
    assert array_definite_short["length"] == 2 and len(array_definite_short["items"]) == 1
    assert array_definite_parse_error["length"] == 2 and array_definite_parse_error["items"] == []

    map_indefinite_empty, _ = decode_module._parse_cbor_item(b"\xbf", 0)
    map_indefinite_missing_value, _ = decode_module._parse_cbor_item(b"\xbf\x61a", 0)
    map_indefinite_parse_error, _ = decode_module._parse_cbor_item(b"\xbf\xd8", 0)
    map_definite_empty, _ = decode_module._parse_cbor_item(b"\xa1", 0)
    map_definite_parse_error, _ = decode_module._parse_cbor_item(b"\xa1\xd8", 0)
    assert map_indefinite_empty["entries"] == []
    assert map_indefinite_missing_value["entries"] == []
    assert map_indefinite_parse_error["entries"] == []
    assert map_definite_empty["entries"] == []
    assert map_definite_parse_error["entries"] == []

    monkeypatch.setattr(
        decode_module,
        "_read_cbor_length",
        lambda *_args, **_kwargs: (None, 1),
        raising=False,
    )
    with pytest.raises(decode_module._CborDecodingError, match="Invalid indefinite length for unsigned integer"):
        decode_module._parse_cbor_item(b"\x00", 0)
    with pytest.raises(decode_module._CborDecodingError, match="Invalid indefinite length for negative integer"):
        decode_module._parse_cbor_item(b"\x20", 0)
    with pytest.raises(decode_module._CborDecodingError, match="Invalid indefinite length for CBOR tag"):
        decode_module._parse_cbor_item(b"\xc0", 0)


def test_parse_simple_major_type_values_and_structure_to_value_fallback_branches():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._parse_cbor_item(b"\xf4", 0)[0]["value"] is False
    assert decode_module._parse_cbor_item(b"\xf6", 0)[0]["type"] == "null"
    assert decode_module._parse_cbor_item(b"\xf7", 0)[0]["type"] == "undefined"
    assert decode_module._parse_cbor_item(b"\xf0", 0)[0]["summary"] == "simple(16)"

    assert decode_module._structure_to_value({"majorType": 7, "type": "null"}) is None
    assert decode_module._structure_to_value({"majorType": 7, "type": "undefined"}) is None
    assert decode_module._structure_to_value({"majorType": 7, "type": "boolean", "value": 0}) is False
    assert decode_module._structure_to_value({"majorType": 2, "hex": "not-hex"}) == b""
    assert decode_module._structure_to_value({"majorType": 3, "value": 123}) == ""
    assert decode_module._structure_to_value({"majorType": 4, "items": 123}) == []
    assert decode_module._structure_to_value({"majorType": 5, "entries": 123}) == {}

    map_value = decode_module._structure_to_value(
        {
            "majorType": 5,
            "entries": [
                "not-a-mapping",
                {
                    "key": {"majorType": 0, "value": 1},
                    "value": {"majorType": 0, "value": 7},
                },
                {
                    "key": None,
                    "value": {"majorType": 0, "value": 9},
                },
            ],
        }
    )
    assert map_value == {1: 7}

    tagged = decode_module._structure_to_value(
        {
            "majorType": 6,
            "tag": 33,
            "value": {"majorType": 0, "value": 42},
        }
    )
    assert tagged == {"tag": 33, "value": 42}


def test_expand_cbor_value_falls_back_to_make_json_safe_for_unknown_types(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    class _Unknown:
        pass

    monkeypatch.setattr(
        decode_module,
        "make_json_safe",
        lambda value: {"safeType": type(value).__name__},
        raising=False,
    )

    expanded = decode_module._expand_cbor_value(_Unknown())
    assert expanded == {"safeType": "_Unknown"}


def test_try_decode_authenticator_data_returns_structured_payload_on_success(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        decode_module,
        "_describe_authenticator_data_bytes",
        lambda _data: {"parsed": True},
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_binary_summary",
        lambda data, encoding=None: {"hex": data.hex(), "encoding": encoding},
        raising=False,
    )

    result = decode_module._try_decode_authenticator_data(b"\x01\x02", "hex")
    assert result == {
        "format": "Authenticator data (binary)",
        "inputEncoding": "hex",
        "decoded": {"parsed": True},
        "binary": {"hex": "0102", "encoding": "hex"},
    }
