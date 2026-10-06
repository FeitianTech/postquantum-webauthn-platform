"""Tests of text behavior."""

import base64
import json

from server.app.decoder.encode import text as encode_text
from tests.app.security.ceremony_helpers import b64u


def test_encode_payload_text_cbor_is_deterministic_across_equivalent_permutations():
    variants = [
        json.dumps(
            {
                "z": 1,
                "nested": {"b": 2, "a": 1},
                "k": [3, {"y": 2, "x": 1}],
                "blob": {"alpha": [1, 2], "beta": {"m": True, "n": None}},
            }
        ),
        json.dumps(
            {
                "blob": {"beta": {"n": None, "m": True}, "alpha": [1, 2]},
                "k": [3, {"x": 1, "y": 2}],
                "nested": {"a": 1, "b": 2},
                "z": 1,
            }
        ),
        json.dumps(
            {
                "nested": {"a": 1, "b": 2},
                "z": 1,
                "blob": {"alpha": [1, 2], "beta": {"m": True, "n": None}},
                "k": [3, {"x": 1, "y": 2}],
            }
        ),
    ]

    encoded_hex_values = [
        encode_text.encode_payload_text(payload, "cbor")["data"]["binary"]["hex"]
        for payload in variants
    ]

    assert len(set(encoded_hex_values)) == 1


def test_encode_pem_normalizes_label_and_wraps_64_columns():
    source_bytes = bytes(range(80))
    payload = {
        "value": {"bytes": list(source_bytes)},
        "pemLabel": "x509 certificate",
    }

    result = encode_text.encode_payload_text(json.dumps(payload), "pem")

    assert result["success"] is True
    assert result["type"] == "PEM (encoded)"

    pem = result["data"]["pem"]
    lines = pem.splitlines()
    assert lines[0] == "-----BEGIN X509_CERTIFICATE-----"
    assert lines[-1] == "-----END X509_CERTIFICATE-----"

    body_lines = lines[1:-1]
    assert body_lines
    assert all(len(line) <= 64 for line in body_lines)
    if len(body_lines) > 1:
        assert all(len(line) == 64 for line in body_lines[:-1])

    restored = base64.b64decode("".join(body_lines))
    assert restored == source_bytes


def test_encode_der_extracts_nested_binary_payload():
    payload_bytes = b"\x01\x02\x03\x04\x05"
    encoded = encode_text.encode_payload_text(
        json.dumps({"binary": {"base64url": b64u(payload_bytes)}}),
        "der",
    )

    assert encoded["success"] is True
    assert encoded["type"] == "DER (encoded)"
    assert encoded["data"]["binary"]["hex"] == payload_bytes.hex()
    assert encoded["data"]["derBase64"] == base64.b64encode(payload_bytes).decode("ascii")
