from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.x509.oid import NameOID

from fido2 import cose
from fido2.utils import ByteBuffer


def _self_signed_cert_der(private_key):
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "postquantum-webauthn-test")]
    )
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


def _ecdsa_signature_with_high_s(*, private_key, message: bytes, order: int, high_s: bool) -> bytes:
    while True:
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        _, s = utils.decode_dss_signature(signature)
        if (s > order // 2) is high_s:
            return signature


def test_parse_der_length_supports_short_long_and_error_cases():
    assert cose._parse_der_length(memoryview(b"\x05"), 0) == (5, 1)
    assert cose._parse_der_length(memoryview(b"\x82\x01\x00"), 0) == (256, 3)

    with pytest.raises(ValueError, match="Indefinite length"):
        cose._parse_der_length(memoryview(b"\x80"), 0)

    with pytest.raises(ValueError, match="truncated"):
        cose._parse_der_length(memoryview(b"\x82\x01"), 0)

    with pytest.raises(ValueError, match="truncated"):
        cose._parse_der_length(memoryview(b"\x01"), 1)


def test_extract_certificate_signature_and_public_key_info_from_der_certificate():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert_der = _self_signed_cert_der(private_key)

    signature_info = cose.extract_certificate_signature_info(cert_der)
    public_key_info = cose.extract_certificate_public_key_info(cert_der)

    assert signature_info["tbs_certificate"]
    assert signature_info["signature"]
    assert isinstance(signature_info["signature_algorithm_oid"], str)

    assert public_key_info["subject_public_key_info"]
    assert public_key_info["subject_public_key"]
    assert isinstance(public_key_info["algorithm_oid"], str)


def test_require_canonical_ecdsa_signature_enforces_low_s_and_der_shape():
    private_key = ec.generate_private_key(ec.SECP256R1())
    message = b"postquantum-webauthn-cose-signature"

    low_s_signature = _ecdsa_signature_with_high_s(
        private_key=private_key,
        message=message,
        order=cose._SECP256R1_ORDER,
        high_s=False,
    )
    high_s_signature = _ecdsa_signature_with_high_s(
        private_key=private_key,
        message=message,
        order=cose._SECP256R1_ORDER,
        high_s=True,
    )

    assert (
        cose._require_canonical_ecdsa_signature(low_s_signature, cose._SECP256R1_ORDER)
        == low_s_signature
    )

    with pytest.raises(ValueError, match="low-S"):
        cose._require_canonical_ecdsa_signature(high_s_signature, cose._SECP256R1_ORDER)

    with pytest.raises(ValueError, match="trailing data"):
        cose._require_canonical_ecdsa_signature(low_s_signature + b"\x00", cose._SECP256R1_ORDER)

    with pytest.raises(ValueError, match="DER SEQUENCE"):
        cose._require_canonical_ecdsa_signature(b"\x01", cose._SECP256R1_ORDER)
