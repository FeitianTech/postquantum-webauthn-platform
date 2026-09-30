from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from server.app.webauthn.attestation import (
    certificate_names as attestation_certificate_names,
)
from server.app.webauthn.attestation import (
    certificate_public_keys as attestation_certificate_public_keys,
)


def _self_signed_cert_der() -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attestation-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=5))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_format_helpers(attestation_module):
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Demo CN"),
        ]
    )
    assert attestation_certificate_names._extract_common_names(name) == ["Demo CN"]


def test_fallback_certificate_serialization_and_unknown_public_key_info_helpers(monkeypatch, certificate_public_keys, attestation_module):
    monkeypatch.setattr(
        certificate_public_keys,
        "extract_certificate_public_key_info",
        lambda _cert: {
            "algorithm_name": "ML-DSA",
            "algorithm_oid": "2.16.840.1.101.3.4.3.18",
            "ml_dsa_parameter_set": "ML-DSA-65",
            "subject_public_key": b"\x01\x02",
            "subject_public_key_info": b"\x30\x03\x01\x02\x03",
            "wrapped_subject_public_key": b"\x04\x04ABCD",
            "algorithm_parameters": b"\x05\x00",
            "ml_dsa_parameter_details": {
                "public_key_length": 1952,
                "signature_length": 3309,
                "claimed_nist_level": 3,
            },
        },
    )

    info, summary = attestation_certificate_public_keys._build_unknown_public_key_info(b"\x01\x02", RuntimeError("bad cert"))
    assert info["algorithm"]["mlDsaParameterSet"] == "ML-DSA-65"
    assert info["algorithm"]["claimedNistLevel"] == 3
    assert info["publicKeyBase64"] == base64.b64encode(b"\x01\x02").decode("ascii")
    assert summary


def test_public_key_serialization_paths(monkeypatch, attestation_module):
    ec_info = attestation_certificate_public_keys._serialize_public_key_info(ec.generate_private_key(ec.SECP256R1()).public_key())
    rsa_info = attestation_certificate_public_keys._serialize_public_key_info(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())
    ed_info = attestation_certificate_public_keys._serialize_public_key_info(ed25519.Ed25519PrivateKey.generate().public_key())

    assert ec_info["type"] == "ECC"
    assert rsa_info["type"] == "RSA"
    assert ed_info["algorithm"]["name"] == "EdDSA"

    class _UnknownKey:
        def public_bytes(self, *, encoding, format):
            return b"spki"

    unknown_info = attestation_certificate_public_keys._serialize_public_key_info(_UnknownKey())
    assert unknown_info["type"] == "_UnknownKey"
    assert unknown_info["algorithm"]["name"] == "_UnknownKey"
