import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _build_auth_and_attestation_bytes() -> tuple[bytes, bytes]:
    from fido2.cose import CoseKey
    from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData

    credential_id = b"encode-format-cred"
    public_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, public_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        1,
        credential_data,
    )
    attestation_object = AttestationObject.create("none", auth_data, {})
    return bytes(auth_data), bytes(attestation_object)


def _build_der_certificate() -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "encoder-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=7))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_encode_payload_text_dispatches_core_formats_with_real_payloads():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    auth_data_bytes, attestation_bytes = _build_auth_and_attestation_bytes()
    cert_bytes = _build_der_certificate()

    json_result = encode_module.encode_payload_text('{"a":1}', "json")
    assert json_result["success"] is True
    assert json_result["type"].startswith("JSON")

    credential_result = encode_module.encode_payload_text(
        json.dumps({"id": "cred", "type": "public-key", "response": {}}),
        "public key credential",
    )
    assert credential_result["success"] is True
    assert credential_result["type"].startswith("PublicKeyCredential")

    client_result = encode_module.encode_payload_text(
        json.dumps(
            {
                "type": "webauthn.create",
                "challenge": "AQID",
                "origin": "https://example.com",
            }
        ),
        "webauthn client data",
    )
    assert client_result["success"] is True

    auth_result = encode_module.encode_payload_text(
        json.dumps({"authenticatorData": _b64url(auth_data_bytes)}),
        "authenticator data",
    )
    assert auth_result["success"] is True

    attestation_result = encode_module.encode_payload_text(
        json.dumps({"attestationObject": _b64url(attestation_bytes)}),
        "attestation object",
    )
    assert attestation_result["success"] is True

    x509_result = encode_module.encode_payload_text(
        json.dumps({"certificate": base64.b64encode(cert_bytes).decode("ascii")}),
        "x.509 certificate",
    )
    assert x509_result["success"] is True


def test_encode_payload_text_reports_empty_invalid_json_and_unsupported_format():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="input is empty"):
        encode_module.encode_payload_text("   ", "json")

    with pytest.raises(ValueError, match="expects a JSON document"):
        encode_module.encode_payload_text("not-json", "json")

    with pytest.raises(ValueError, match="Unsupported encoder format"):
        encode_module.encode_payload_text("{}", "unknown-target")


def test_hex_base64_base64url_binary_and_der_pem_helpers():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    hex_result = encode_module._encode_hex_value({"value": {"hex": "aabb"}})
    assert hex_result["data"]["hex"] == "aabb"

    b64_result = encode_module._encode_base64_value({"value": {"hex": "aabb"}})
    assert b64_result["data"]["base64"] == "qrs="

    b64url_result = encode_module._encode_base64url_value({"value": {"hex": "aabb"}})
    assert b64url_result["data"]["base64url"] == "qrs"

    binary_result = encode_module._encode_binary_value({"value": {"hex": "aabb"}})
    assert binary_result["data"]["bytes"] == [170, 187]

    der_result = encode_module._encode_der_value({"value": {"hex": "aabb"}})
    assert der_result["data"]["derBase64"] == "qrs="

    pem_result = encode_module._encode_pem_value({"value": {"hex": "aabb"}, "pemLabel": "Demo Label"})
    assert "BEGIN DEMO_LABEL" in pem_result["data"]["pem"]


def test_extract_binary_input_and_ctap_numeric_mapping_error_paths():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._extract_binary_input({"authenticatorData": "aabb"}, "authenticatorData") == b"\xaa\xbb"
    assert encode_module._extract_binary_input(b"\x01\x02", "field") == b"\x01\x02"

    with pytest.raises(ValueError, match="Unable to interpret"):
        encode_module._require_bytes({"oops": True}, "field")

    with pytest.raises(ValueError, match="numeric keys"):
        encode_module._sanitize_ctap_numeric_mapping({"bad": 1})

    with pytest.raises(ValueError, match="Duplicate field"):
        encode_module._sanitize_ctap_numeric_mapping({1: "a", "01": "b"})


def test_ctap_webauthn_encoder_validates_required_fields_and_can_encode_response():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="Missing field"):
        encode_module._encode_ctap_webauthn_value({"01": "example.com"})

    encoded = encode_module._encode_ctap_webauthn_value(
        {
            "02": _b64url(b"\xff" * 37),
            "03": _b64url(b"\xfe" * 64),
            "08": {"bytes": [1, 2, 3]},
        }
    )
    assert encoded["success"] is True
    assert encoded["type"].startswith("CBOR (CTAP/WebAuthn Data)")
    assert "ctapDecoded" in encoded["data"]
