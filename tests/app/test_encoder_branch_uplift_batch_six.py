from __future__ import annotations

import base64
from decimal import Decimal

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_extract_ctap_numeric_payload_salvages_numeric_fields_from_mixed_mappings():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    parsed = {
        "ignored": "value",
        "1": _b64url(b"\x01" * 32),
        "2": {"id": "example.com", "name": "Example"},
        "3": {"id": _b64url(b"user-id"), "name": "alice"},
        "4": [{"type": "public-key", "alg": -7}],
    }

    numeric_map, ctap_type = encode_module._extract_ctap_numeric_payload(parsed)

    assert ctap_type == "makeCredentialRequest"
    assert set(numeric_map) >= {1, 2, 3, 4}
    assert numeric_map[2]["id"] == "example.com"


def test_extract_ctap_numeric_payload_raises_when_no_mappable_candidates_exist():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="Unable to locate CTAP/WebAuthn"):
        encode_module._extract_ctap_numeric_payload("plain-string")


@pytest.mark.parametrize(
    ("mapping", "expected_message"),
    [
        ({}, "expects at least one CTAP field"),
        ({2: "not-bytes", 3: _b64url(b"sig")}, "must be binary data for GetAssertion response"),
        ({2: _b64url(b"\xAA" * 37)}, "Missing field 0x01"),
        ({1: _b64url(b"\xBB" * 32), 2: "not-an-object"}, r"Field 0x02 \(rp\) must be an object"),
        ({1: "packed", 2: "not-bytes"}, "must be binary data"),
        ({1: object(), 2: _b64url(b"\xCC" * 32)}, "Unable to classify CTAP/WebAuthn data"),
    ],
)
def test_classify_ctap_numeric_mapping_reports_specific_contract_errors(mapping, expected_message):
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match=expected_message):
        encode_module._classify_ctap_numeric_mapping(mapping)


def test_coerce_ctap_numeric_key_and_nested_key_sanitization_edges():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._coerce_ctap_numeric_key("   ") is None
    assert encode_module._coerce_ctap_numeric_key("0xzz") is None
    assert encode_module._coerce_ctap_numeric_key(object()) is None

    with pytest.raises(ValueError, match="must be non-negative"):
        encode_module._coerce_ctap_numeric_key(-1)

    assert encode_module._sanitize_nested_extra_key("7 ( )") == "7"


def test_canonical_encoder_dispatches_supported_core_types_and_tag_rules():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    encoder = encode_module._CanonicalCBOREncoder()

    assert encoder._encode(True) == b"\xf5"
    assert encoder._encode(None) == b"\xf6"
    assert encoder._encode(encode_module.undefined) == b"\xf7"
    assert encoder._encode([1, 2]) == b"\x82\x01\x02"
    assert encoder._encode(b"AB") == b"\x42AB"
    assert encoder._encode("ok") == b"\x62ok"
    assert encoder._encode(encode_module.CBORSimpleValue(5)) == bytes([0xE5])
    assert isinstance(encoder._encode(Decimal("1.5")), bytes)

    assert encoder._encode_tag(encode_module.CBORTag(1, 2)) == b"\xc1\x02"

    class _NegativeTag:
        tag = -1
        value = 2

    with pytest.raises(ValueError, match="non-negative integers"):
        encoder._encode_tag(_NegativeTag())

    assert encoder._encode_cbor_simple_value(encode_module.CBORSimpleValue(10)) == bytes([0xEA])
    assert encoder._encode_cbor_simple_value(encode_module.CBORSimpleValue(32)) == b"\xf8\x20"


def test_require_certificate_bytes_and_binary_decoding_error_paths():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="Unable to decode certificate PEM contents"):
        encode_module._require_certificate_bytes(
            {"pem": "-----BEGIN CERTIFICATE-----\n====\n-----END CERTIFICATE-----"},
            0,
        )

    with pytest.raises(ValueError, match="Unable to decode certificate PEM contents"):
        encode_module._require_certificate_bytes(
            {"pem": "-----BEGIN CERTIFICATE-----\nA===\n-----END CERTIFICATE-----"},
            1,
        )

    assert encode_module._maybe_decode_bytes("   ") == b""
    assert encode_module._maybe_decode_bytes({"hex": "zz"}) is None
    assert encode_module._maybe_decode_bytes({"base64": "A"}) is None
    assert encode_module._maybe_decode_bytes({"base64url": "A"}) is None
    assert (
        encode_module._maybe_decode_bytes(
            {"pem": "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"}
        )
        is None
    )


def test_encode_payload_text_errors_when_alias_resolves_without_handler(monkeypatch):
    encode_module = pytest.importorskip("server.app.decoder.encode")

    patched_handlers = dict(encode_module._ENCODING_HANDLERS)
    patched_handlers.pop("json", None)
    monkeypatch.setattr(encode_module, "_ENCODING_HANDLERS", patched_handlers, raising=False)

    with pytest.raises(ValueError, match="Unsupported encoder format"):
        encode_module.encode_payload_text('{"ok":true}', "json")