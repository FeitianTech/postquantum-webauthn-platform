import base64
import json

import cbor2
import pytest


def _pad_base64(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_encode_payload_text_rejects_empty_input():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="Encoder input is empty"):
        encode_module.encode_payload_text("   ", "json")


def test_encode_payload_text_rejects_non_json_document():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="expects a JSON document"):
        encode_module.encode_payload_text("not-json", "json")


def test_encode_pem_normalizes_label_and_wraps_64_columns():
    decoder_module = pytest.importorskip("server.app.decoder")

    source_bytes = bytes(range(80))
    payload = {
        "value": {"bytes": list(source_bytes)},
        "pemLabel": "x509 certificate",
    }

    result = decoder_module.encode_payload_text(json.dumps(payload), "pem")

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
    decoder_module = pytest.importorskip("server.app.decoder")

    payload_bytes = b"\x01\x02\x03\x04\x05"
    encoded = decoder_module.encode_payload_text(
        json.dumps({"binary": {"base64url": _b64url(payload_bytes)}}),
        "der",
    )

    assert encoded["success"] is True
    assert encoded["type"] == "DER (encoded)"
    assert encoded["data"]["binary"]["hex"] == payload_bytes.hex()
    assert encoded["data"]["derBase64"] == base64.b64encode(payload_bytes).decode("ascii")


def test_encode_base64url_accepts_bytes_array_payload():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    source = bytes([0, 1, 2, 253, 254, 255])
    result = encode_module._encode_base64url_value({"bytes": list(source)})

    assert result["success"] is True
    assert result["type"] == "Base64URL (encoded)"
    assert result["data"]["base64url"] == _b64url(source)


def test_encode_attestation_statement_converts_sig_and_x5c_entries():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    first_cert = b"first-cert"
    first_cert_pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(first_cert).decode("ascii")
        + "\n-----END CERTIFICATE-----"
    )

    statement = encode_module._encode_attestation_statement(
        {
            "sig": {"hex": "aabbcc"},
            "x5c": [
                {"pem": first_cert_pem},
                {"base64url": _b64url(b"second-cert")},
            ],
            "alg": -7,
            "customBinary": {"base64": base64.b64encode(b"blob-data").decode("ascii")},
        }
    )

    assert statement["sig"] == bytes.fromhex("aabbcc")
    assert statement["x5c"] == [first_cert, b"second-cert"]
    assert statement["alg"] == -7
    assert statement["customBinary"] == b"blob-data"


def test_require_certificate_bytes_rejects_unrecoverable_pem_entry():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="Unable to decode certificate PEM contents"):
        encode_module._require_certificate_bytes({"pem": "%%%%"}, 0)


def test_encode_ctap_webauthn_rejects_negative_numeric_field_ids():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="must be non-negative"):
        encode_module._encode_ctap_webauthn_value(
            {
                -1: "AA",
                2: _b64url(b"\x00" * 32),
            }
        )


def test_encode_cbor_uses_ctap_metadata_codehex_prefix_when_provided():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    challenge_hash = b"\x11" * 32
    payload = {
        "ctap": {
            "codeHex": "0x02",
            "kind": "command",
        },
        "ctapDecoded": {
            "getAssertionRequest": {
                "rpId": "example.com",
                "clientDataHash": {"base64url": _b64url(challenge_hash)},
            }
        },
    }

    result = encode_module._encode_cbor_value(payload)

    assert result["success"] is True
    assert result["type"] == "CBOR (canonical) (encoded getAssertionRequest)"
    assert result["data"]["ctap"]["code"] == 2
    assert result["data"]["ctap"]["kind"] == "command"

    raw_bytes = base64.urlsafe_b64decode(_pad_base64(result["data"]["binary"]["base64url"]))
    assert raw_bytes[0] == 0x02

    encoded_mapping = cbor2.loads(raw_bytes[1:])
    assert encoded_mapping[1] == "example.com"
    assert encoded_mapping[2] == challenge_hash
