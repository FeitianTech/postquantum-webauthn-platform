import base64
import hashlib

from server.app.webauthn.attestation import certificates as attestation_certificates


def test_serialize_attestation_certificate_returns_none_for_empty_bytes():
    assert attestation_certificates.serialize_attestation_certificate(b"") is None


def test_serialize_attestation_certificate_returns_fallback_shape_for_malformed_der():
    malformed_der = b"\x30\x82\x01\x00"

    result = attestation_certificates.serialize_attestation_certificate(malformed_der)

    assert isinstance(result, dict)
    assert result["error"].startswith("Unable to parse attestation certificate:")
    assert isinstance(result["parseError"], str)
    assert result["raw"] == malformed_der.hex()
    assert result["derBase64"] == base64.b64encode(malformed_der).decode("ascii")
    assert result["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert result["pem"].strip().endswith("-----END CERTIFICATE-----")
    assert result["fingerprints"] == {
        "sha256": hashlib.sha256(malformed_der).hexdigest(),
        "sha1": hashlib.sha1(malformed_der).hexdigest(),
        "md5": hashlib.md5(malformed_der).hexdigest(),
    }
    assert isinstance(result["publicKeyInfo"], dict)
    assert "summary" in result
