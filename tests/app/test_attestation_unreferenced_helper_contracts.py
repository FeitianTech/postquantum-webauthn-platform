from __future__ import annotations

import base64
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from fido2.utils import ByteBuffer


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


def test_datetime_coercion_bytes_and_leaf_certificate_helpers():
    attestation_module = pytest.importorskip("server.app.attestation")

    naive = datetime(2026, 1, 1, 12, 0, 0)
    assert attestation_module._ensure_utc_datetime(naive).tzinfo == timezone.utc

    class _FakeCert:
        not_valid_before_utc = datetime(2026, 1, 1, tzinfo=timezone.utc)
        not_valid_after = datetime(2026, 2, 1)

    before = attestation_module._certificate_datetime(_FakeCert(), "not_valid_before")
    after = attestation_module._certificate_datetime(_FakeCert(), "not_valid_after")
    assert before.tzinfo == timezone.utc
    assert after.tzinfo == timezone.utc

    assert attestation_module._coerce_bytes(ByteBuffer(b"abc")) == b"abc"
    assert attestation_module._coerce_bytes(memoryview(b"xyz")) == b"xyz"
    assert attestation_module._coerce_bytes("abc") is None

    cert_der = _self_signed_cert_der()
    cert_b64 = base64.b64encode(cert_der).decode("ascii")
    attestation_object = SimpleNamespace(att_stmt={"x5c": [cert_b64]})
    assert attestation_module._extract_attestation_leaf_certificate(attestation_object) == cert_der
    assert attestation_module._extract_attestation_leaf_certificate(SimpleNamespace(att_stmt={"x5c": []})) is None


def test_trusted_ca_config_and_fingerprint_helpers(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    monkeypatch.setitem(attestation_module.app.config, "TRUSTED_ATTESTATION_CA_SUBJECTS", ["CN=Root"])
    monkeypatch.setitem(attestation_module.app.config, "TRUSTED_ATTESTATION_CA_FINGERPRINTS", ("abc", "def"))

    assert attestation_module._trusted_ca_subjects() == {"CN=Root"}
    assert attestation_module._trusted_ca_fingerprints() == {"ABC", "DEF"}

    fingerprint = attestation_module._certificate_fingerprint(b"cert")
    assert isinstance(fingerprint, str)
    assert fingerprint == fingerprint.upper()


def test_metadata_lookup_subject_description_and_format_helpers():
    attestation_module = pytest.importorskip("server.app.attestation")

    verifier = SimpleNamespace(find_entry_by_aaguid=lambda _aaguid: {"ok": True})
    found = attestation_module._find_metadata_entry_for_aaguid(
        verifier,
        bytes.fromhex("00112233445566778899aabbccddeeff"),
    )
    assert found == {"ok": True}
    assert attestation_module._find_metadata_entry_for_aaguid(verifier, b"") is None

    class _BrokenVerifier:
        def find_entry_by_aaguid(self, _aaguid):
            raise RuntimeError("boom")

    assert (
        attestation_module._find_metadata_entry_for_aaguid(
            _BrokenVerifier(),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
        )
        is None
    )

    cert_der = _self_signed_cert_der()
    cert = x509.load_der_x509_certificate(cert_der)
    assert "CN=" in attestation_module._describe_certificate_subject(cert)

    assert attestation_module._format_algorithm_component(" RSASSA PSS ") == "RSASSAPSS"
    assert attestation_module._format_algorithm_component("—") == ""

    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Demo CN"),
        ]
    )
    assert attestation_module._extract_common_names(name) == ["Demo CN"]


def test_fallback_certificate_serialization_and_unknown_public_key_info_helpers(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    monkeypatch.setattr(
        attestation_module,
        "extract_certificate_public_key_info",
        lambda _cert: {
            "algorithm_name": "ML-DSA",
            "algorithm_oid": "2.16.840.1.101.3.4.3.18",
            "ml_dsa_parameter_set": "ML-DSA-65",
            "subject_public_key": b"\x01\x02",
            "subject_public_key_info": b"\x30\x03\x01\x02\x03",
            "wrapped_subject_public_key": b"\x04\x04ABCD",
            "algorithm_parameters": b"\x05\x00",
        },
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_load_oqs_signature_details",
        lambda _mechanism: {
            "claimed-nist-level": 3,
            "length-signature": 3293,
            "length-public-key": 1952,
            "description": "ML-DSA mechanism",
            "sig-name": "ML-DSA-65",
            "sig-family": "post-quantum",
        },
        raising=False,
    )

    info, summary = attestation_module._build_unknown_public_key_info(b"\x01\x02", RuntimeError("bad cert"))
    assert info["algorithm"]["mlDsaParameterSet"] == "ML-DSA-65"
    assert info["algorithm"]["claimedNistLevel"] == 3
    assert info["publicKeyBase64"] == base64.b64encode(b"\x01\x02").decode("ascii")
    assert summary

    monkeypatch.setattr(
        attestation_module,
        "_build_unknown_public_key_info",
        lambda _cert, _err: ({"type": "Unknown", "algorithm": {"name": "Unknown"}}, [("Type", "Unknown")]),
        raising=False,
    )
    fallback = attestation_module._serialize_attestation_certificate_fallback(
        b"\x30\x82\x01\x00",
        ValueError("parse failed"),
    )
    assert fallback["parseError"] == "parse failed"
    assert fallback["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "Fingerprints" in fallback["summary"]


def test_oqs_details_loader_and_public_key_serialization_paths(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    class _FakeSignature:
        def __init__(self, _mechanism):
            self.details = {"claimed-nist-level": 5}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    fake_oqs = SimpleNamespace(Signature=_FakeSignature)
    monkeypatch.setitem(sys.modules, "oqs", fake_oqs)
    details = attestation_module._load_oqs_signature_details("ML-DSA-87")
    assert details["mechanism"] == "ML-DSA-87"
    assert details["claimed-nist-level"] == 5

    class _BrokenSignatureModule:
        class Signature:
            def __init__(self, _mechanism):
                raise RuntimeError("cannot init")

    monkeypatch.setitem(sys.modules, "oqs", _BrokenSignatureModule)
    assert attestation_module._load_oqs_signature_details("ML-DSA-65") is None

    ec_info = attestation_module._serialize_public_key_info(ec.generate_private_key(ec.SECP256R1()).public_key())
    rsa_info = attestation_module._serialize_public_key_info(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())
    ed_info = attestation_module._serialize_public_key_info(ed25519.Ed25519PrivateKey.generate().public_key())

    assert ec_info["type"] == "ECC"
    assert rsa_info["type"] == "RSA"
    assert ed_info["algorithm"]["name"] == "EdDSA"

    class _UnknownKey:
        def public_bytes(self, *, encoding, format):
            return b"spki"

    unknown_info = attestation_module._serialize_public_key_info(_UnknownKey())
    assert unknown_info["type"] == "_UnknownKey"
    assert unknown_info["algorithm"]["name"] == "_UnknownKey"
