from __future__ import annotations

import base64

import pytest

from tests.fido2.attestation.test_attestation import _GSR2_DER


def _pem_block(der_bytes: bytes) -> str:
    body = base64.b64encode(der_bytes).decode("ascii")
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----"


def test_decode_public_key_credential_includes_signature_and_user_handle_summaries(monkeypatch, pipeline):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    def _decode_binary(value):
        if value == "sig":
            return b"\xaa\xbb", "base64"
        if value == "uh":
            return b"\x01\x02", "base64url"
        return None

    monkeypatch.setattr(pipeline, "_decode_binary_field", _decode_binary)

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


def test_decode_binary_payload_uses_authenticator_data_path_when_other_binary_decoders_fail(monkeypatch, pipeline):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(pipeline, "_try_decode_utf8", lambda _data: None)
    monkeypatch.setattr(pipeline, "_try_decode_certificate_bytes", lambda _data, _enc: None)
    monkeypatch.setattr(pipeline, "_try_decode_attestation_object", lambda _data, _enc: None)
    monkeypatch.setattr(
        pipeline,
        "_try_decode_authenticator_data",
        lambda _data, enc: {"format": "Authenticator data (binary)", "inputEncoding": enc},
    )

    result = decode_module._decode_binary_payload(b"raw", "hex")
    assert result["format"] == "Authenticator data (binary)"
    assert result["inputEncoding"] == "hex"


def test_decode_binary_input_has_no_lenient_fallback_when_strict_decoding_fails(monkeypatch):
    """There is no second, non-validating attempt to fall back to.

    The pipeline used to retry with ``urlsafe_b64decode`` and no ``validate``,
    which discards characters outside the alphabet -- that is how prose was
    accepted as base64url. Strict failure is now the end of the road.
    """

    decode_module = pytest.importorskip("server.app.decoder.decode")

    original_b64decode = base64.b64decode

    def _patched_b64decode(*args, **kwargs):
        if kwargs.get("validate"):
            raise ValueError("strict decode failed")
        return original_b64decode(*args, **kwargs)

    monkeypatch.setattr(base64, "b64decode", _patched_b64decode)

    with pytest.raises(ValueError, match="does not appear to be valid"):
        decode_module._decode_binary_input("AQID")


def test_read_cbor_length_reads_arguments_and_rejects_reserved_additional_information():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._read_cbor_length(25, b"\x00\x01", 0) == (1, 2)
    assert decode_module._read_cbor_length(27, b"\x00" * 8, 0) == (0, 8)
    with pytest.raises(decode_module._CborDecodingError, match="additional information 30 is reserved"):
        decode_module._read_cbor_length(30, b"\x00" * 8, 1)


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"", "the data ends where an item should start"),
        (b"\x5f", "indefinite-length byte string has no break byte"),
        (b"\x5f\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\x7f", "indefinite-length text string has no break byte"),
        (b"\x7f\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\x9f\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\x82\x01", "array declares 2 items; the data ends after 1"),
        (b"\x82\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\xbf", "indefinite-length map has no break byte"),
        (b"\xbf\x61a", 'map key "a" has no value'),
        (b"\xbf\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\xa1", "map declares 1 entry; the data ends after 0"),
        (b"\xa1\xd8", "the head needs 1 more byte; 0 remain"),
        (b"\x1f", "indefinite length is not allowed for this major type"),
        (b"\x3f", "indefinite length is not allowed for this major type"),
        (b"\xdf", "indefinite length is not allowed for this major type"),
    ],
)
def test_cbor_parser_rejects_partial_and_invalid_items(data, reason):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    with pytest.raises(decode_module._CborDecodingError) as caught:
        decode_module._parse_cbor_item(data, 0)

    assert caught.value.reason == reason


def test_cbor_parser_accepts_an_empty_indefinite_array_and_closes_partial_containers_only_when_lenient():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    empty, end = decode_module._parse_cbor_item(b"\x9f\xff", 0)
    assert (empty["length"], empty["indefinite"], end) == (0, True, 2)

    short_array, _, skipped = decode_module.decode_item(b"\x82\x01", lenient=True)
    assert short_array["length"] == 1
    assert short_array["declaredLength"] == 2
    assert [entry["code"] for entry in skipped] == ["truncated"]

    orphan_key, _, skipped = decode_module.decode_item(b"\xbf\x61a", lenient=True)
    assert orphan_key["entries"] == []
    assert [entry["code"] for entry in skipped] == ["missing-map-value"]


def test_parse_simple_major_type_values_and_structure_to_value_fallback_branches():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._parse_cbor_item(b"\xf4", 0)[0]["value"] is False
    assert decode_module._parse_cbor_item(b"\xf6", 0)[0]["type"] == "null"
    assert decode_module._parse_cbor_item(b"\xf7", 0)[0]["type"] == "undefined"
    assert decode_module._parse_cbor_item(b"\xf0", 0)[0]["summary"] == "simple(16)"

    assert decode_module._structure_to_value({"majorType": 7, "type": "null"}) is None
    assert decode_module._structure_to_value({"majorType": 7, "type": "undefined"}) == decode_module.CborDiagnostic(
        "undefined"
    )
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


def test_expand_cbor_value_falls_back_to_make_json_safe_for_unknown_types(monkeypatch, pipeline):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    class _Unknown:
        pass

    monkeypatch.setattr(
        pipeline,
        "make_json_safe",
        lambda value: {"safeType": type(value).__name__},
    )

    expanded = decode_module._expand_cbor_value(_Unknown())
    assert expanded == {"safeType": "_Unknown"}


def test_try_decode_authenticator_data_returns_structured_payload_on_success(monkeypatch, pipeline):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        pipeline,
        "_describe_authenticator_data_bytes",
        lambda _data: {"parsed": True},
    )
    monkeypatch.setattr(
        pipeline,
        "_binary_summary",
        lambda data, encoding=None: {"hex": data.hex(), "encoding": encoding},
    )

    result = decode_module._try_decode_authenticator_data(b"\x01\x02", "hex")
    assert result == {
        "format": "Authenticator data (binary)",
        "inputEncoding": "hex",
        "decoded": {"parsed": True},
        "binary": {"hex": "0102", "encoding": "hex"},
        "findings": [],
    }
