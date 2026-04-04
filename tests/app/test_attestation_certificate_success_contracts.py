from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier


def _build_certificate(
    subject_key,
    *,
    issuer_key=None,
    subject_cn: str = "Subject",
    issuer_cn: str = "Issuer",
    is_ca: bool = False,
    custom_extensions: list[x509.ExtensionType] | None = None,
) -> bytes:
    issuer_key = issuer_key or subject_key
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )

    for extension in custom_extensions or []:
        builder = builder.add_extension(extension, critical=False)

    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        cert = builder.sign(private_key=issuer_key, algorithm=None)
    else:
        cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())

    return cert.public_bytes(serialization.Encoding.DER)


def test_serialize_attestation_certificate_rsa_success_path_includes_extensions_and_summary():
    attestation_module = pytest.importorskip("server.app.attestation")

    custom_device_identifier = x509.UnrecognizedExtension(
        ObjectIdentifier("1.3.6.1.4.1.41482.2"),
        b"\x04\x04demo",
    )
    custom_transports = x509.UnrecognizedExtension(
        ObjectIdentifier("1.3.6.1.4.1.45724.2.1.1"),
        b"\x03\x02\x00\x03",
    )

    cert_bytes = _build_certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        subject_cn="Demo Authenticator",
        issuer_cn="Demo Root",
        custom_extensions=[custom_device_identifier, custom_transports],
    )

    result = attestation_module.serialize_attestation_certificate(cert_bytes)

    assert result is not None
    assert result["signatureAlgorithm"]
    assert result["issuer"]
    assert result["subject"]
    assert result["publicKeyInfo"]["type"] == "RSA"
    assert result["fingerprints"]["sha256"]
    assert "X509v3 extensions" in result["summary"]
    assert any(ext["oid"] == "1.3.6.1.4.1.41482.2" for ext in result["extensions"])
    assert any(ext["oid"] == "1.3.6.1.4.1.45724.2.1.1" for ext in result["extensions"])


def test_serialize_attestation_certificate_handles_ec_and_ed25519_public_key_variants():
    attestation_module = pytest.importorskip("server.app.attestation")

    ec_cert = _build_certificate(
        ec.generate_private_key(ec.SECP256R1()),
        subject_cn="EC Device",
        issuer_cn="EC Root",
    )
    ec_result = attestation_module.serialize_attestation_certificate(ec_cert)
    assert ec_result["publicKeyInfo"]["type"] == "ECC"
    assert ec_result["publicKeyInfo"]["curve"]

    ed_cert = _build_certificate(
        ed25519.Ed25519PrivateKey.generate(),
        subject_cn="Ed Device",
        issuer_cn="Ed Root",
    )
    ed_result = attestation_module.serialize_attestation_certificate(ed_cert)
    assert "Ed" in ed_result["publicKeyInfo"]["type"]
    assert ed_result["publicKeyInfo"]["algorithm"]["name"] == "EdDSA"


def test_extract_attestation_details_populates_chain_and_extension_outputs(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    cert_bytes = _build_certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        subject_cn="Chain Device",
        issuer_cn="Chain Root",
    )

    class _ClientData:
        b64 = None

        def __bytes__(self):
            return b'{"type":"webauthn.create"}'

    class _AttestationObject:
        fmt = "packed"
        att_stmt = {"x5c": [cert_bytes]}

        def __bytes__(self):
            return b"attestation-object"

    fake_registration = SimpleNamespace(
        response=SimpleNamespace(
            attestation_object=_AttestationObject(),
            client_data=_ClientData(),
        ),
        client_extension_results={"credProps": {"rk": True}},
    )

    monkeypatch.setattr(
        attestation_module.RegistrationResponse,
        "from_dict",
        lambda _response: fake_registration,
        raising=False,
    )

    (
        attestation_format,
        attestation_statement,
        attestation_object_b64,
        client_data_b64,
        client_extensions,
        attestation_certificate,
        attestation_certificates,
    ) = attestation_module.extract_attestation_details({"dummy": True})

    assert attestation_format == "packed"
    assert "x5c" in attestation_statement
    assert isinstance(attestation_object_b64, str) and attestation_object_b64
    assert isinstance(client_data_b64, str) and client_data_b64
    assert client_extensions["credProps"]["rk"] is True
    assert attestation_certificate is not None
    assert attestation_certificates and isinstance(attestation_certificates[0], dict)


def test_extract_certificate_aaguid_reads_aaguid_extension_bytes():
    attestation_module = pytest.importorskip("server.app.attestation")

    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    extension = x509.UnrecognizedExtension(attestation_module.AAGUID_EXTENSION_OID, b"\x04\x10" + aaguid)
    cert_bytes = _build_certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        custom_extensions=[extension],
    )

    extracted = attestation_module._extract_certificate_aaguid(cert_bytes)
    assert extracted == aaguid
    assert attestation_module._extract_certificate_aaguid(b"not-a-cert") == b""


def test_serialize_extension_value_handles_known_extension_types_from_real_certificate():
    attestation_module = pytest.importorskip("server.app.attestation")

    cert_bytes = _build_certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        subject_cn="Ext Subject",
        issuer_cn="Ext Issuer",
    )
    cert = x509.load_der_x509_certificate(cert_bytes)

    extension_values = {
        ext.oid.dotted_string: attestation_module._serialize_extension_value(ext)
        for ext in cert.extensions
    }

    assert "2.5.29.14" in extension_values
    assert "Hex value" in extension_values["2.5.29.14"]
    assert "2.5.29.35" in extension_values
    assert "2.5.29.19" in extension_values


def test_derive_certificate_algorithm_info_formats_signature_components_consistently():
    attestation_module = pytest.importorskip("server.app.attestation")

    assert (
        attestation_module._derive_certificate_algorithm_info(
            {
                "algorithm": {"name": "ecdsa"},
                "hash": {"name": "sha-256"},
            }
        )
        == "ECDSA_SHA256"
    )

    assert (
        attestation_module._derive_certificate_algorithm_info(
            {
                "algorithm": "ed25519",
                "hash": None,
            }
        )
        == "ED25519_SHA512"
    )
