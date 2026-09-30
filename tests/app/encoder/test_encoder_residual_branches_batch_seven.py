from __future__ import annotations

import pytest

from server.app.decoder.encode import binary_decode as encode_binary_decode
from server.app.decoder.encode import binary_extract as encode_binary_extract
from server.app.decoder.encode import ctap_fields as encode_ctap_fields
from server.app.decoder.encode import handlers_cbor as encode_handlers_cbor


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_encode_cbor_value_never_reads_a_plain_map_as_ctap():
    # A root map with CTAP member names was read as a makeCredential response.

    payload = {
        "fmt": "none",
        "authData": b"\x00" * 37,
    }

    encoded = encode_handlers_cbor._encode_cbor_value(payload)

    assert encoded["success"] is True
    assert encoded["type"] == "CBOR (canonical) (encoded)"
    assert "ctapDecoded" not in encoded["data"]
    assert encoded["data"]["binary"]["hex"].startswith("a263666d74646e6f6e65")


def test_sanitize_numeric_mapping_and_pem_label_defaults():
    assert encode_binary_extract._normalize_pem_label(" !!! ") == "DATA"


def test_primitive_coercion_and_attestation_statement_residual_paths():
    assert encode_ctap_fields._ensure_int(7, "field") == 7
    with pytest.raises(ValueError, match="integer value"):
        encode_ctap_fields._ensure_int("not-an-int", "field")

    assert encode_ctap_fields._ensure_bool(True, "flag") is True

    assert encode_ctap_fields._encode_attestation_statement(None) is None
    assert encode_ctap_fields._encode_attestation_statement(b"\xAA") == b"\xAA"
    assert encode_ctap_fields._encode_credential_descriptor(b"\xBB") == b"\xBB"


def test_require_certificate_bytes_handles_empty_pem_decoding_and_non_mapping_failure():
    with pytest.raises(ValueError, match="Unable to decode certificate PEM contents"):
        encode_binary_decode._require_certificate_bytes({"pem": "===="}, 0)

    with pytest.raises(ValueError, match=r"x5c\[1\]"):
        encode_binary_decode._require_certificate_bytes({"pem": 123}, 1)
