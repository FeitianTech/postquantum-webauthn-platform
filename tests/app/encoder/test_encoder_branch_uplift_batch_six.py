from __future__ import annotations

import base64

import pytest

from server.app.decoder.encode import binary_decode as encode_binary_decode


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


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
