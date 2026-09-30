from __future__ import annotations

import base64
from decimal import Decimal

import cbor2
import pytest

from server.app.decoder import cbor_canonical
from server.app.decoder.encode import binary_decode as encode_binary_decode


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_canonical_encoder_dispatches_supported_core_types_and_tag_rules():
    encoder = cbor_canonical._CanonicalCBOREncoder()

    assert encoder._encode(True) == b"\xf5"
    assert encoder._encode(None) == b"\xf6"
    assert encoder._encode(cbor2.undefined) == b"\xf7"
    assert encoder._encode([1, 2]) == b"\x82\x01\x02"
    assert encoder._encode(b"AB") == b"\x42AB"
    assert encoder._encode("ok") == b"\x62ok"
    assert encoder._encode(cbor2.CBORSimpleValue(5)) == bytes([0xE5])
    with pytest.raises(ValueError, match="Decimal"):
        encoder._encode(Decimal("1.5"))

    assert encoder._encode_tag(cbor2.CBORTag(1, 2)) == b"\xc1\x02"

    class _NegativeTag:
        tag = -1
        value = 2

    with pytest.raises(ValueError, match="non-negative integers"):
        encoder._encode_tag(_NegativeTag())

    assert encoder._encode_cbor_simple_value(cbor2.CBORSimpleValue(10)) == bytes([0xEA])
    assert encoder._encode_cbor_simple_value(cbor2.CBORSimpleValue(32)) == b"\xf8\x20"


def test_require_certificate_bytes_and_binary_decoding_error_paths():
    with pytest.raises(ValueError, match="Unable to decode certificate PEM contents"):
        encode_binary_decode._require_certificate_bytes(
            {"pem": "-----BEGIN CERTIFICATE-----\n====\n-----END CERTIFICATE-----"},
            0,
        )

    with pytest.raises(ValueError, match="Unable to decode certificate PEM contents"):
        encode_binary_decode._require_certificate_bytes(
            {"pem": "-----BEGIN CERTIFICATE-----\nA===\n-----END CERTIFICATE-----"},
            1,
        )

    assert encode_binary_decode._maybe_decode_bytes("   ") == b""
    assert encode_binary_decode._maybe_decode_bytes({"hex": "zz"}) is None
    assert encode_binary_decode._maybe_decode_bytes({"base64": "A"}) is None
    assert encode_binary_decode._maybe_decode_bytes({"base64url": "A"}) is None
    assert (
        encode_binary_decode._maybe_decode_bytes(
            {"pem": "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"}
        )
        is None
    )
