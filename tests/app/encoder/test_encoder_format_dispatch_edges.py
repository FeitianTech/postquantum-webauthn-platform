import base64

import pytest

from server.app.decoder.encode import binary_decode as encode_binary_decode
from server.app.decoder.encode import ctap_numeric as encode_ctap_numeric
from server.app.decoder.encode import handlers_basic as encode_handlers_basic
from server.app.decoder.encode import handlers_cbor as encode_handlers_cbor
from server.app.decoder.encode import text as encode_text


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_encode_payload_text_dispatches_json():
    json_result = encode_text.encode_payload_text('{"a":1}', "json")
    assert json_result["success"] is True
    assert json_result["type"].startswith("JSON")



def test_encode_payload_text_reports_empty_invalid_json_and_unsupported_format():
    with pytest.raises(ValueError, match="input is empty"):
        encode_text.encode_payload_text("   ", "json")

    with pytest.raises(ValueError, match="expects a JSON document"):
        encode_text.encode_payload_text("not-json", "json")

    with pytest.raises(ValueError, match="Unsupported encoder format"):
        encode_text.encode_payload_text("{}", "unknown-target")


def test_der_and_pem_helpers():
    der_result = encode_handlers_basic._encode_der_value({"value": {"hex": "aabb"}})
    assert der_result["data"]["derBase64"] == "qrs="

    pem_result = encode_handlers_basic._encode_pem_value({"value": {"hex": "aabb"}, "pemLabel": "Demo Label"})
    assert "BEGIN DEMO_LABEL" in pem_result["data"]["pem"]


def test_require_bytes_and_ctap_numeric_mapping_error_paths():
    with pytest.raises(ValueError, match="Unable to interpret"):
        encode_binary_decode._require_bytes({"oops": True}, "field")

    with pytest.raises(ValueError, match="numeric keys"):
        encode_ctap_numeric._sanitize_ctap_numeric_mapping({"bad": 1})

    with pytest.raises(ValueError, match="Duplicate field"):
        encode_ctap_numeric._sanitize_ctap_numeric_mapping({1: "a", "01": "b"})


def test_ctap_webauthn_encoder_validates_required_fields_and_can_encode_response():
    with pytest.raises(ValueError, match="Missing field"):
        encode_handlers_cbor._encode_ctap_webauthn_value({"01": "example.com"})

    encoded = encode_handlers_cbor._encode_ctap_webauthn_value(
        {
            "02": _b64url(b"\xff" * 37),
            "03": _b64url(b"\xfe" * 64),
            "08": {"bytes": [1, 2, 3]},
        }
    )
    assert encoded["success"] is True
    assert encoded["type"].startswith("CBOR (CTAP/WebAuthn Data)")
    assert "ctapDecoded" in encoded["data"]
