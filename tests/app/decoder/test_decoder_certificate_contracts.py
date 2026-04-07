import base64

import pytest

from tests.fido2.attestation.test_attestation import _GSR2_DER


def _pem_block(der_bytes: bytes) -> str:
    body = base64.b64encode(der_bytes).decode("ascii")
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_decode_pem_certificates_ignores_invalid_blocks_and_keeps_valid_certificates():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    invalid_block = "-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----"
    pem_bundle = "\n".join([_pem_block(_GSR2_DER), invalid_block, _pem_block(_GSR2_DER)])

    result = decode_module._decode_pem_certificates(pem_bundle)

    assert result["format"] == "X.509 certificate (PEM)"
    assert result["inputEncoding"] == "pem"
    decoded = result["decoded"]
    assert isinstance(decoded, dict)
    assert "rawPem" in decoded
    assert decoded["rawPem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "certificates" in decoded
    assert len(decoded["certificates"]) == 2
    assert all(isinstance(cert.get("fingerprints"), dict) for cert in decoded["certificates"])


def test_decode_pem_certificates_rejects_payload_without_any_valid_pem_certificate():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    pem_text = "-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----"

    with pytest.raises(ValueError, match="No PEM certificate data found"):
        decode_module._decode_pem_certificates(pem_text)


def test_try_decode_certificate_bytes_returns_none_for_malformed_der_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    malformed_der = _GSR2_DER[:24]

    assert decode_module._try_decode_certificate_bytes(malformed_der, "base64url") is None


def test_codec_api_decodes_der_certificate_payload_successfully():
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    payload = _b64url(_GSR2_DER)

    with config_module.app.test_client() as client:
        response = client.post(
            "/api/codec",
            json={"mode": "decode", "payload": payload},
        )

    assert response.status_code == 200
    body = response.get_json()
    assert body["success"] is True
    assert body["type"].startswith("X.509 certificate")
    assert isinstance(body["data"], dict)
    parsed = body["data"].get("parsedX5c")
    assert isinstance(parsed, dict)
    assert isinstance(parsed.get("fingerprints"), dict)
