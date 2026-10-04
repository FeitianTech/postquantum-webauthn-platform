from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from server.app.webauthn.attestation import (
    certificate_extensions as attestation_certificate_extensions,
)


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


def test_serialize_extension_value_handles_known_extension_types_from_real_certificate():
    cert_bytes = _build_certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        subject_cn="Ext Subject",
        issuer_cn="Ext Issuer",
    )
    cert = x509.load_der_x509_certificate(cert_bytes)

    extension_values = {
        ext.oid.dotted_string: attestation_certificate_extensions._serialize_extension_value(ext)
        for ext in cert.extensions
    }

    assert "2.5.29.14" in extension_values
    assert "Hex value" in extension_values["2.5.29.14"]
    assert "2.5.29.35" in extension_values
    assert "2.5.29.19" in extension_values
