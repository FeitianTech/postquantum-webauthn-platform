"""Certificate parsing contracts for ML-DSA, backed by real certificates.

These replace the contract tests that pinned the hand-rolled DER/ASN.1 parser
that used to live in ``fido2.cose``.  That parser was heuristic -- it scanned a
certificate for anything the right length -- so the old tests asserted its
custom error strings and its lenient unwrapping.  Parsing is now delegated to
``cryptography``, so what is worth pinning is the behaviour, not the internals:
real certificates parse correctly, and malformed input is rejected.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from fido2.cose import (
    describe_mldsa_oid_name,
    extract_certificate_public_key_info,
    extract_certificate_signature_info,
)

PARAMETER_SETS = [
    ("ML-DSA-44", mldsa.MLDSA44PrivateKey, 1312, 2420, "2.16.840.1.101.3.4.3.17"),
    ("ML-DSA-65", mldsa.MLDSA65PrivateKey, 1952, 3309, "2.16.840.1.101.3.4.3.18"),
    ("ML-DSA-87", mldsa.MLDSA87PrivateKey, 2592, 4627, "2.16.840.1.101.3.4.3.19"),
]


def _self_signed(private_key) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PQC leaf")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, None)
    )
    return cert.public_bytes(Encoding.DER)


@pytest.mark.parametrize("label,key_cls,key_len,sig_len,oid", PARAMETER_SETS)
def test_public_key_info_from_a_real_mldsa_certificate(label, key_cls, key_len, sig_len, oid):
    info = extract_certificate_public_key_info(_self_signed(key_cls.generate()))

    assert info["algorithm_oid"] == oid
    assert info["ml_dsa_parameter_set"] == label
    # The raw key is unwrapped from SubjectPublicKeyInfo at its exact FIPS 204 size.
    assert len(info["subject_public_key"]) == key_len
    # FIPS 204 sizes, not the pre-standard Dilithium Round 3 values.
    assert info["ml_dsa_parameter_details"]["signature_length"] == sig_len
    assert info["ml_dsa_parameter_details"]["public_key_length"] == key_len


@pytest.mark.parametrize("label,key_cls,key_len,sig_len,oid", PARAMETER_SETS)
def test_signature_info_from_a_real_mldsa_certificate(label, key_cls, key_len, sig_len, oid):
    info = extract_certificate_signature_info(_self_signed(key_cls.generate()))

    assert info["signature_algorithm_oid"] == oid
    assert len(info["signature"]) == sig_len
    assert info["tbs_certificate"]


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x30", id="bare-sequence-tag"),
        pytest.param(b"\x30\x82\x01\x00", id="length-exceeds-data"),
        pytest.param(b"not a certificate at all", id="not-der"),
        pytest.param(b"\x30\x03\x02\x01\x00", id="well-formed-der-but-not-a-cert"),
    ],
)
def test_malformed_certificates_are_rejected(payload):
    """Garbage must raise rather than be scanned for something key-shaped.

    The previous hand-rolled parser searched the blob for any substructure of
    the expected length, so several of these decoded "successfully".
    """

    with pytest.raises(ValueError):
        extract_certificate_public_key_info(payload)
    with pytest.raises(ValueError):
        extract_certificate_signature_info(payload)


@pytest.mark.parametrize("label,key_cls,key_len,sig_len,oid", PARAMETER_SETS)
def test_truncated_certificate_is_rejected(label, key_cls, key_len, sig_len, oid):
    der = _self_signed(key_cls.generate())

    with pytest.raises(ValueError):
        extract_certificate_public_key_info(der[: len(der) // 2])


def test_oid_names_are_reported_for_each_parameter_set():
    assert describe_mldsa_oid_name("2.16.840.1.101.3.4.3.17") == "ML-DSA-44"
    assert describe_mldsa_oid_name("2.16.840.1.101.3.4.3.18") == "ML-DSA-65"
    assert describe_mldsa_oid_name("2.16.840.1.101.3.4.3.19") == "ML-DSA-87"
    assert describe_mldsa_oid_name("1.2.840.113549.1.1.11") is None
