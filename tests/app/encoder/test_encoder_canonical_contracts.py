from types import SimpleNamespace

import pytest

from server.app.decoder import cbor_canonical
from server.app.decoder.encode import binary_extract as encode_binary_extract
from server.app.decoder.encode import ctap_numeric as encode_ctap_numeric
from server.app.decoder.encode import handlers_basic as encode_handlers_basic
from server.app.decoder.encode import handlers_cbor as encode_handlers_cbor


def test_normalize_encoding_format_aliases_and_validation_errors():
    assert encode_handlers_basic._normalize_encoding_format("JSON") == "json"
    assert encode_handlers_basic._normalize_encoding_format("EDN (exact bytes)") == "edn"
    assert encode_handlers_basic._normalize_encoding_format("CBOR (CTAP/WebAuthn Data)") == "ctap-webauthn"

    with pytest.raises(ValueError, match="must be a string"):
        encode_handlers_basic._normalize_encoding_format(123)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Unsupported encoder format"):
        encode_handlers_basic._normalize_encoding_format("totally-unknown")


def test_ctap_numeric_key_coercion_and_classification_paths():
    assert encode_ctap_numeric._coerce_ctap_numeric_key("0x02") == 2
    assert encode_ctap_numeric._coerce_ctap_numeric_key("02 (clientDataHash)") == 2
    assert encode_ctap_numeric._coerce_ctap_numeric_key("not-a-key") is None

    with pytest.raises(ValueError, match="must be non-negative"):
        encode_ctap_numeric._coerce_ctap_numeric_key(-1)

    classified = encode_ctap_numeric._classify_ctap_numeric_mapping(
        {
            1: "example.com",
            2: b"\x11" * 32,
        }
    )
    assert classified == "getAssertionRequest"

    with pytest.raises(ValueError, match="Missing field 0x02"):
        encode_ctap_numeric._classify_ctap_numeric_mapping({1: b"\x00" * 32})


def test_extract_ctap_numeric_payload_and_encode_ctap_webauthn_with_extra_fields():
    nested = {
        "wrapper": {
            "02 (authData)": {"base64": "A" * 52},
            "03 (signature)": {"hex": "aabbcc"},
            "07 (largeBlobKey)": {"bytes": [1, 2, 3]},
        }
    }

    numeric_map, ctap_type = encode_ctap_numeric._extract_ctap_numeric_payload(nested)
    assert ctap_type == "getAssertionResponse"
    assert 2 in numeric_map and 3 in numeric_map

    response = encode_handlers_cbor._encode_ctap_webauthn_value(nested)
    assert response["success"] is True
    assert response["type"].startswith("CBOR (CTAP/WebAuthn Data)")
    assert "ctapDecoded" in response["data"]


def test_canonical_encoder_map_ordering_and_duplicate_detection():
    encoder = cbor_canonical._CanonicalCBOREncoder()

    encoded = encoder.encode({"b": 2, "a": 1})
    canonicalized = encoder.canonicalize_structure({"b": 2, "a": 1})

    assert isinstance(encoded, bytes) and encoded
    assert list(canonicalized.keys()) == ["a", "b"]

    with pytest.raises(ValueError, match="reserved"):
        encoder._encode_cbor_simple_value(SimpleNamespace(value=24))


def test_canonical_float_encoding_and_unsigned_integer_helpers():
    nan_bytes = cbor_canonical._encode_canonical_float(float("nan"))
    assert nan_bytes == b"\xf9\x7e\x00"

    finite_bytes = cbor_canonical._encode_canonical_float(1.5)
    assert finite_bytes.startswith((b"\xf9", b"\xfa", b"\xfb"))

    assert cbor_canonical._encode_unsigned_integer(0, 10) == bytes([10])

    with pytest.raises(ValueError, match="non-negative"):
        cbor_canonical._encode_unsigned_integer(0, -1)

    with pytest.raises(ValueError, match="64 bits"):
        cbor_canonical._encode_unsigned_integer(0, 1 << 80)


def test_extract_generic_binary_payload_and_pem_label_helpers():
    payload = {
        "meta": {"ignored": True},
        "container": {
            "payload": [
                {"other": "x"},
                {"binary": {"hex": "aabbcc"}},
            ]
        },
    }

    extracted = encode_binary_extract._extract_generic_binary_payload(payload)
    assert extracted == b"\xaa\xbb\xcc"

    pem_response = encode_handlers_basic._encode_pem_value(
        {
            "value": {"hex": "aabbccdd"},
            "pemLabel": " demo cert ",
        }
    )
    assert pem_response["success"] is True
    assert "BEGIN DEMO_CERT" in pem_response["data"]["pem"]

    with pytest.raises(ValueError, match="Unable to extract binary payload"):
        encode_binary_extract._extract_generic_binary_payload({"value": None})


def test_encode_cose_value_and_prepare_response_helpers():
    cose_response = encode_handlers_cbor._encode_cose_value(
        {"cose": {1: 2, 3: -7, -1: 1, -2: b"\x01", -3: b"\x02"}}
    )
    assert cose_response["success"] is True
    assert cose_response["type"].startswith("COSE")

    prepared = encode_handlers_basic._prepare_encoder_response(
        "JSON",
        {"value": {"bytes": b"\x01\x02"}},
        qualifier="encoded",
        warnings=["warn"],
    )
    assert prepared["type"] == "JSON (encoded)"
    assert prepared["malformed"] == ["warn"]
    assert prepared["data"]["value"]["bytes"] == "AQI"
