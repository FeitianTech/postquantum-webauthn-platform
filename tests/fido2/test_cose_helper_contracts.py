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


def test_extract_subject_public_key_from_spki_and_parse_algorithm_info():
    private_key = ec.generate_private_key(ec.SECP256R1())
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    public_key_payload = cose._extract_subject_public_key_from_spki(spki)
    algorithm_oid, algorithm_params = cose._parse_spki_algorithm_info(spki)

    assert public_key_payload and public_key_payload[0] == 0x04
    assert algorithm_oid == "1.2.840.10045.2.1"
    assert isinstance(algorithm_params, (bytes, bytearray))

    with pytest.raises(ValueError, match="SEQUENCE"):
        cose._extract_subject_public_key_from_spki(b"\x31\x00")


def test_scan_certificate_for_subject_public_key_info_finds_embedded_spki():
    private_key = ec.generate_private_key(ec.SECP256R1())
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    blob = b"\x00\xff" + spki + b"\xaa\xbb"
    spki_der, algorithm_oid, _params, payload = cose._scan_certificate_for_subject_public_key_info(
        memoryview(blob)
    )

    assert spki_der == spki
    assert algorithm_oid == "1.2.840.10045.2.1"
    assert payload and payload[0] == 0x04


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


def test_mldsa_oid_helpers_and_der_candidate_unwrap_helpers():
    details = cose.describe_mldsa_oid("2.16.840.1.101.3.4.3.18")
    assert details is not None
    assert details["mlDsaParameterSet"] == "ML-DSA-65"
    assert cose.describe_mldsa_oid_name("2.16.840.1.101.3.4.3.18") == "ML-DSA-65"
    assert cose.describe_mldsa_oid_name("1.2.3") is None

    nested = b"\x30\x08\x04\x06\x04\x04ABCD"
    candidate = cose._find_mldsa_der_candidate(memoryview(nested), 0, len(nested), 4)
    assert candidate == b"ABCD"

    unwrapped, wrapped = cose._unwrap_mldsa_subject_public_key(b"\x04\x04WXYZ")
    assert unwrapped == b"WXYZ"
    assert wrapped == b"\x04\x04WXYZ"


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


def test_coerce_mldsa_public_key_bytes_accepts_buffers_and_public_key_objects():
    assert cose._coerce_mldsa_public_key_bytes(b"\x04\x04test") == b"test"
    assert cose._coerce_mldsa_public_key_bytes(ByteBuffer(b"buffer-key")) == b"buffer-key"

    ec_public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    coerced = cose._coerce_mldsa_public_key_bytes(ec_public_key)
    assert coerced and coerced[0] == 0x04

    with pytest.raises(TypeError, match="Unable to coerce"):
        cose._coerce_mldsa_public_key_bytes(object())


def test_require_oqs_returns_module_when_present_and_raises_when_missing(monkeypatch):
    fake_module = object()
    monkeypatch.setattr(cose, "oqs", fake_module, raising=False)
    assert cose._require_oqs() is fake_module

    monkeypatch.setattr(cose, "oqs", None, raising=False)
    monkeypatch.setattr(cose, "_oqs_import_error", RuntimeError("missing"), raising=False)

    with pytest.raises(RuntimeError, match="ML-DSA verification requires"):
        cose._require_oqs()
